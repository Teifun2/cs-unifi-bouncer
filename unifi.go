package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

func dial(ctx context.Context) (unifi.Client, error) {
	client, err := unifi.NewClient(
		&unifi.ClientConfig{
			URL:      unifiHost,
			User:     unifiUsername,
			Password: unifiPassword,
			APIKey:   unifiAPIKey,
			VerifySSL: !skipTLSVerify,
		},
	)

	if err != nil {
		return nil, err
	}

	return client, nil
}

func (mal *unifiAddrList) initUnifi(ctx context.Context) {

	log.Info().Msg("Connecting to unifi")

	c, err := dial(ctx)
	if err != nil {
		log.Fatal().Err(err).Str("host", unifiHost).Str("username", unifiUsername).Msg("Connection failed")
	}

	mal.c = c
	mal.cacheIpv4 = make(map[string]bool)
	mal.cacheIpv6 = make(map[string]bool)
	mal.firewallGroupsIPv4 = make(map[string]string)
	mal.firewallGroupsIPv6 = make(map[string]string)
	mal.firewallRuleIPv4 = make(map[string]FirewallRuleCache)
	mal.firewallRuleIPv6 = make(map[string]FirewallRuleCache)
	mal.firewallZonePolicyIPv4 = make(map[string]FirewallZonePolicyCache)
	mal.firewallZonePolicyIPv6 = make(map[string]FirewallZonePolicyCache)
	mal.modified = false
	mal.isZoneBased = false
	mal.firewallZones = make(map[string]ZoneCache)

	// Check if zone-based firewall is enabled
	mal.isZoneBased, err = c.IsFeatureEnabled(ctx, unifiSite, "ZONE_BASED_FIREWALL_MIGRATION")

	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get networks")
	}

	log.Info().Msgf("Zone Based Firewall: %t", mal.isZoneBased)

	// Check if firewall groups exist
	groups, err := c.ListFirewallGroup(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall groups")
	}

	for _, group := range groups {
		if strings.Contains(group.Name, "cs-unifi-bouncer-ipv4") {
			mal.firewallGroupsIPv4[group.Name] = group.ID
			for _, member := range group.GroupMembers {
				mal.cacheIpv4[member] = true
			}
		}
		if strings.Contains(group.Name, "cs-unifi-bouncer-ipv6") {
			mal.firewallGroupsIPv6[group.Name] = group.ID
			for _, member := range group.GroupMembers {
				mal.cacheIpv6[member] = true
			}
		}
	}

	// Check if firewall rules exists
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	for _, rule := range rules {
		if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv4") {
			mal.firewallRuleIPv4[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
		if strings.Contains(rule.Name, "cs-unifi-bouncer-ipv6") {
			mal.firewallRuleIPv6[rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
	}

	// Check if firewall policies exists
	if mal.isZoneBased {
		policies, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall policies")
		}

		for _, policy := range policies {
			if strings.Contains(policy.Name, "cs-unifi-bouncer-ipv4") {
				mal.firewallZonePolicyIPv4[policy.Name] = FirewallZonePolicyCache{id: policy.ID, groupId: policy.Source.IPGroupID}
			}
			if strings.Contains(policy.Name, "cs-unifi-bouncer-ipv6") {
				mal.firewallZonePolicyIPv4[policy.Name] = FirewallZonePolicyCache{id: policy.ID, groupId: policy.Source.IPGroupID}
			}
		}
	}

	// Cache Firewall Zones
	if mal.isZoneBased {
		if len(unifiZoneSrc) == 0 || len(unifiZoneDst) == 0 {
			log.Fatal().Msg("At least one unifiZoneSrc and one unifiZoneDst must be configured")
		}

		zones, err := c.ListFirewallZone(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall zones")
		}

		for _, zone := range zones {
			mal.firewallZones[zone.Name] = ZoneCache{id: zone.ID}
		}

		// Check if source and destination zones are defined
		for _, zone := range unifiZoneSrc {
			if _, exists := mal.firewallZones[zone]; !exists {
				log.Fatal().Msgf("Source Zone %s not found", zone)
			}
		}
		for _, zone := range unifiZoneDst {
			if _, exists := mal.firewallZones[zone]; !exists {
				log.Fatal().Msgf("Destination Zone %s not found", zone)
			}
		}
	}
}

// Function to get keys from a map
func getKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// Function to update the firewall group
func (mal *unifiAddrList) updateFirewall(ctx context.Context) {

	if !mal.modified {
		log.Debug().Msg("No changes detected, skipping update")
		return
	}

	// Get all cache IPv4 addresses
	ipv4Addresses := getKeys(mal.cacheIpv4)

	// Calculate the number of groups needed
	numGroupsIPv4 := (len(ipv4Addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of IPv4 groups needed: %d", numGroupsIPv4)

	// Split IPv4 addresses into groups of maxGroupSize
	for i := 0; i < len(ipv4Addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(ipv4Addresses) {
			end = len(ipv4Addresses)
		}
		group := ipv4Addresses[i:end]

		// Get the group ID if it exists
		groupID := ""
		if id, exists := mal.firewallGroupsIPv4["cs-unifi-bouncer-ipv4-"+strconv.Itoa(i/maxGroupSize)]; exists {
			groupID = id
		}

		// Post the firewall group
		groupID = mal.postFirewallGroup(ctx, i/maxGroupSize, groupID, false, group)

		if mal.isZoneBased {
			for _, zoneSrc := range unifiZoneSrc {
				for _, zoneDst := range unifiZoneDst {
					// Get the policy ID if it exists
					policyId := ""
					cachedGroupId := ""
					if policyCache, exists := mal.firewallZonePolicyIPv4[fmt.Sprintf("cs-unifi-bouncer-ipv4-%s->%s-%d", zoneSrc, zoneDst, i/maxGroupSize)]; exists {
						policyId = policyCache.id
						cachedGroupId = policyCache.groupId
					}
					// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
					if groupID != "" && groupID != cachedGroupId {
						mal.postFirewallPolicy(ctx, i/maxGroupSize, policyId, false, groupID, zoneSrc, zoneDst)
					}
				}
			}
		} else {
			// Get the rule ID if it exists
			ruleId := ""
			cachedGroupId := ""
			if ruleCache, exists := mal.firewallRuleIPv4["cs-unifi-bouncer-ipv4-"+strconv.Itoa(i/maxGroupSize)]; exists {
				ruleId = ruleCache.id
				cachedGroupId = ruleCache.groupId
			}

			// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
			if groupID != "" && groupID != cachedGroupId {
				mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, false, groupID)
			}
		}
	}

	// Delete old rules and groups that are no longer needed with an index higher than numGroups
	for i := numGroupsIPv4; ; i++ {
		name := "cs-unifi-bouncer-ipv4-" + strconv.Itoa(i)
		ruleCache, exists := mal.firewallRuleIPv4[name]
		if !exists {
			break
		}

		err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", name)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", name)
			delete(mal.firewallRuleIPv4, name)
		}

		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, ruleCache.groupId)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", name)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", name)
			delete(mal.firewallGroupsIPv4, name)
		}
	}

	// Get all cache IPv6 addresses
	ipv6Addresses := getKeys(mal.cacheIpv6)

	// Calculate the number of groups needed
	numGroupsIPv6 := (len(ipv6Addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of IPv6 groups needed: %d", numGroupsIPv6)

	// Split IPv6 addresses into groups of maxGroupSize
	for i := 0; i < len(ipv6Addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(ipv6Addresses) {
			end = len(ipv6Addresses)
		}
		group := ipv6Addresses[i:end]

		// Get the group ID if it exists
		groupID := ""
		if id, exists := mal.firewallGroupsIPv6["cs-unifi-bouncer-ipv6-"+strconv.Itoa(i/maxGroupSize)]; exists {
			groupID = id
		}

		// Post the firewall group
		groupID = mal.postFirewallGroup(ctx, i/maxGroupSize, groupID, true, group)

		// Get the rule ID if it exists
		ruleId := ""
		cachedGroupId := ""
		if ruleCache, exists := mal.firewallRuleIPv6["cs-unifi-bouncer-ipv6-"+strconv.Itoa(i/maxGroupSize)]; exists {
			ruleId = ruleCache.id
			cachedGroupId = ruleCache.groupId
		}

		// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
		if groupID != "" && groupID != cachedGroupId {
			mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, true, groupID)
		}
	}

	// Delete old groups that are no longer needed with an index higher than numGroups
	for i := numGroupsIPv6; ; i++ {
		groupName := "cs-unifi-bouncer-ipv6-" + strconv.Itoa(i)
		ruleCache, exists := mal.firewallRuleIPv6[groupName]
		if !exists {
			break
		}

		err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", groupName)
			delete(mal.firewallRuleIPv6, groupName)
		}

		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, ruleCache.groupId)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", groupName)
			delete(mal.firewallGroupsIPv6, groupName)
		}
	}
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore adding decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
			return
		}

		if mal.cacheIpv6[*decision.Value] {
			log.Warn().Msgf("Address %s already present", *decision.Value)
		} else {
			mal.modified = true
			mal.cacheIpv6[*decision.Value] = true
		}
	} else {
		if mal.cacheIpv4[*decision.Value] {
			log.Warn().Msgf("Address %s already present", *decision.Value)
		} else {
			mal.modified = true
			mal.cacheIpv4[*decision.Value] = true
		}
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore removing decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	if strings.Contains(*decision.Value, ":") {
		if !useIPV6 {
			log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
			return
		}

		if mal.cacheIpv6[*decision.Value] {
			mal.modified = true
			delete(mal.cacheIpv6, *decision.Value)
		} else {
			log.Warn().Msgf("%s not found in local cache", *decision.Value)
		}
	} else {
		if mal.cacheIpv4[*decision.Value] {
			mal.modified = true
			delete(mal.cacheIpv4, *decision.Value)
		} else {
			log.Warn().Msgf("%s not found in local cache", *decision.Value)
		}
	}
}

func (mal *unifiAddrList) decisionProcess(streamDecision *models.DecisionsStreamResponse) {
	for _, decision := range streamDecision.Deleted {
		mal.remove(decision)
	}
	for _, decision := range streamDecision.New {
		mal.add(decision)
	}
}
