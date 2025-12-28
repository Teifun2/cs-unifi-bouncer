package main

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

func dial() (unifi.Client, error) {
	client, err := unifi.NewClient(
		&unifi.ClientConfig{
			URL:       unifiHost,
			User:      unifiUsername,
			Password:  unifiPassword,
			APIKey:    unifiAPIKey,
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

	c, err := dial()
	if err != nil {
		log.Fatal().Err(err).Str("host", unifiHost).Str("username", unifiUsername).Msg("Connection failed")
	}

	mal.c = c

	mal.blockedAddresses = make(map[bool]map[string]bool)
	mal.blockedAddresses[true] = make(map[string]bool)
	mal.blockedAddresses[false] = make(map[string]bool)

	mal.firewallGroups = make(map[bool]map[string]FirewallGroupCache)
	mal.firewallGroups[true] = make(map[string]FirewallGroupCache)
	mal.firewallGroups[false] = make(map[string]FirewallGroupCache)

	mal.firewallRule = make(map[bool]map[string]FirewallRuleCache)
	mal.firewallRule[true] = make(map[string]FirewallRuleCache)
	mal.firewallRule[false] = make(map[string]FirewallRuleCache)

	mal.firewallZonePolicy = make(map[bool]map[string]FirewallZonePolicyCache)
	mal.firewallZonePolicy[true] = make(map[string]FirewallZonePolicyCache)
	mal.firewallZonePolicy[false] = make(map[string]FirewallZonePolicyCache)

	mal.modified = false
	mal.isZoneBased = false
	mal.firewallZones = make(map[string]ZoneCache)

	// Check if zone-based firewall is enabled
	mal.isZoneBased, err = c.IsFeatureEnabled(ctx, unifiSite, "ZONE_BASED_FIREWALL")

	if err != nil && err.Error() != "not found" {
		log.Fatal().Err(err).Msg("Failed to check the described-features")
	}

	log.Info().Msgf("Zone Based Firewall: %t", mal.isZoneBased)

	// Check if firewall groups exist
	groups, err := c.ListFirewallGroup(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall groups")
	}

	for _, group := range groups {
		if strings.Contains(group.Name, "cs-unifi-bouncer") {
			ipv6 := strings.Contains(group.Name, "ipv6")

			// Cache group with its members
			memberMap := make(map[string]bool)
			for _, member := range group.GroupMembers {
				memberMap[member] = true
				mal.blockedAddresses[ipv6][member] = true
			}
			mal.firewallGroups[ipv6][group.Name] = FirewallGroupCache{
				id:      group.ID,
				members: memberMap,
			}
		}
	}

	// Check if firewall rules exists
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	for _, rule := range rules {
		if strings.Contains(rule.Name, "cs-unifi-bouncer") {
			ipv6 := strings.Contains(rule.Name, "ipv6")

			groupId := ""
			if len(rule.SrcFirewallGroupIDs) > 0 {
				groupId = rule.SrcFirewallGroupIDs[0]
			}
			mal.firewallRule[ipv6][rule.Name] = FirewallRuleCache{id: rule.ID, groupId: groupId}
		}
	}

	// Cache existing firewall zone policies (instead of deleting them)
	if mal.isZoneBased {
		policies, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall policies")
		}

		for _, policy := range policies {
			if strings.Contains(policy.Name, "cs-unifi-bouncer") {
				ipv6 := strings.Contains(policy.Name, "ipv6")
				mal.firewallZonePolicy[ipv6][policy.Name] = FirewallZonePolicyCache{
					id:      policy.ID,
					groupId: policy.Source.IPGroupID,
				}
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

// Function to compare two member sets and determine if they are equal
func membersEqual(cached map[string]bool, newMembers []string) bool {
	if len(cached) != len(newMembers) {
		return false
	}
	for _, member := range newMembers {
		if !cached[member] {
			return false
		}
	}
	return true
}

// Function to update the firewall group
func (mal *unifiAddrList) updateFirewall(ctx context.Context, ipv6 bool) {

	if !mal.modified {
		log.Debug().Msg("No changes detected, skipping update")
		return
	}

	// Run initial audit log cleanup before processing to prevent MongoDB overload
	// This clears any excessive log entries before we start making changes
	if unifiLogCleanup {
		log.Debug().Msg("Running pre-update audit log cleanup...")
		if err := cleanupBouncerAuditEntries(unifiHost, unifiLogCleanupUser, unifiLogCleanupPassword, unifiLogCleanupMinutes); err != nil {
			log.Warn().Err(err).Msg("Pre-update audit log cleanup failed (non-fatal)")
		}
	}

	ipVersionString := "ipv4"
	if ipv6 {
		ipVersionString = "ipv6"
	}

	// Get all cached addresses
	addresses := getKeys(mal.blockedAddresses[ipv6])

	// Calculate the number of groups needed
	numGroups := (len(addresses) + maxGroupSize - 1) / maxGroupSize
	log.Info().Msgf("Number of %s groups needed: %d", ipVersionString, numGroups)

	// Split addresses into groups of maxGroupSize
	for i := 0; i < len(addresses); i += maxGroupSize {
		end := i + maxGroupSize
		if end > len(addresses) {
			end = len(addresses)
		}
		group := addresses[i:end]

		// Get the group ID if it exists and check if members changed
		groupName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, i/maxGroupSize)
		groupID := ""
		groupChanged := true
		if cache, exists := mal.firewallGroups[ipv6][groupName]; exists {
			groupID = cache.id
			// Check if members are the same - skip update if no changes
			if membersEqual(cache.members, group) {
				groupChanged = false
				log.Debug().Msgf("Firewall group %s unchanged, skipping update", groupName)
			}
		}

		// Post the firewall group only if it changed or is new
		if groupChanged {
			groupID = mal.postFirewallGroup(ctx, groupID, groupName, ipv6, group)
		}

		// Used to track if new policies were posted to know if we need to reorder them later
		var newPoliciesPosted bool

		if mal.isZoneBased {
			for _, zoneSrc := range unifiZoneSrc {
				for _, zoneDst := range unifiZoneDst {
					// Get the policy ID if it exists
					policyName := fmt.Sprintf("cs-unifi-bouncer-%s-%s->%s-%d", ipVersionString, zoneSrc, zoneDst, i/maxGroupSize)
					policyId := ""
					cachedGroupId := ""
					if policyCache, exists := mal.firewallZonePolicy[ipv6][policyName]; exists {
						policyId = policyCache.id
						cachedGroupId = policyCache.groupId
					}
					// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
					if groupID != "" && groupID != cachedGroupId {
						newPoliciesPosted = true
						mal.postFirewallPolicy(ctx, policyId, policyName, ipv6, groupID, zoneSrc, zoneDst)
					}
				}
			}
			// Reorder policies after all have been generated (if enabled in config)
			if unifiPolicyReordering && (newPoliciesPosted || !mal.initialReorderingDone) {
				newPoliciesPosted = false
				mal.initialReorderingDone = true
				mal.reorderFirewallPolicies(ctx)
			}

		} else {
			// Get the rule ID if it exists
			ruleName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, i/maxGroupSize)
			ruleId := ""
			cachedGroupId := ""
			if ruleCache, exists := mal.firewallRule[ipv6][ruleName]; exists {
				ruleId = ruleCache.id
				cachedGroupId = ruleCache.groupId
			}

			// Post the firewall rule, skip if the group ID is the same as the cached one (no changes)
			if groupID != "" && groupID != cachedGroupId {
				mal.postFirewallRule(ctx, i/maxGroupSize, ruleId, ruleName, ipv6, groupID)
			}
		}
	}

	// Delete old firewall rules
	for ruleName, ruleCache := range mal.firewallRule[ipv6] {
		// Check if the rule index is lower than numGroups
		parts := strings.Split(ruleName, "-")
		index, err := strconv.Atoi(parts[4])
		if err != nil {
			log.Warn().Msgf("Invalid rule index in name: %s", ruleName)
			continue
		}
		// If isZoneBased, then delete all rules independent of index
		if !mal.isZoneBased && index < numGroups {
			continue
		}
		// Delete the old firewall rule
		err = mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", ruleName)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", ruleName)
			delete(mal.firewallRule[ipv6], ruleName)
		}
	}

	// Delete old firewall policies
	for policyName, policyCache := range mal.firewallZonePolicy[ipv6] {
		// Check if the policy index is higher than numGroups
		parts := strings.Split(policyName, "-")
		index, err := strconv.Atoi(parts[6])
		if err != nil {
			log.Warn().Msgf("Invalid policy index in name: %s", policyName)
			continue
		}

		// Check if unifiZoneSrc contains the src of the existing policy
		validSrc := slices.Contains(unifiZoneSrc, parts[4])
		validDst := slices.Contains(unifiZoneDst, strings.ReplaceAll(parts[5], ">", ""))

		// If isZoneBased is false or if targeted zones are out of scope
		// then delete these policies independent of index
		if mal.isZoneBased && validSrc && validDst && index < numGroups {
			continue
		}
		// Delete the old firewall policy
		err = mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, policyCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall policy: %s", policyName)
		} else {
			log.Info().Msgf("Deleted old firewall policy: %s", policyName)
			delete(mal.firewallZonePolicy[ipv6], policyName)
		}
	}

	// Delete old firewall groups
	for groupName, groupCache := range mal.firewallGroups[ipv6] {
		// Check if the group index is higher than numGroups
		parts := strings.Split(groupName, "-")
		index, err := strconv.Atoi(parts[4])
		if err != nil {
			log.Warn().Msgf("Invalid group index in name: %s", groupName)
			continue
		}
		if index < numGroups {
			continue
		}
		// Delete the old firewall group
		err = mal.c.DeleteFirewallGroup(ctx, unifiSite, groupCache.id)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", groupName)
		} else {
			log.Info().Msgf("Deleted old firewall group: %s", groupName)
			delete(mal.firewallGroups[ipv6], groupName)
		}
	}

	// Clean up audit log entries to prevent MongoDB CPU overload
	// This is critical for UDM/UCG devices where the admin_activity_log
	// can grow very large and cause the control plane to become unresponsive
	if unifiLogCleanup {
		log.Debug().Msg("Running audit log cleanup...")
		if err := cleanupBouncerAuditEntries(unifiHost, unifiLogCleanupUser, unifiLogCleanupPassword, unifiLogCleanupMinutes); err != nil {
			log.Warn().Err(err).Msg("Audit log cleanup failed (non-fatal)")
		}
	}
}

func (mal *unifiAddrList) add(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore adding decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("new decisions from %s: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Origin, *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	ipv6 := strings.Contains(*decision.Value, ":")

	if ipv6 && !useIPV6 {
		log.Info().Msgf("Ignore adding address %s (IPv6 disabled)", *decision.Value)
		return
	}

	if mal.blockedAddresses[ipv6][*decision.Value] {
		log.Warn().Msgf("Address %s already present", *decision.Value)
	} else {
		mal.modified = true
		mal.blockedAddresses[ipv6][*decision.Value] = true
	}
}

func (mal *unifiAddrList) remove(decision *models.Decision) {

	if *decision.Type != "ban" {
		log.Debug().Msgf("Ignore removing decision type %s", *decision.Type)
		return
	}

	log.Info().Msgf("removed decisions: IP: %s | Scenario: %s | Duration: %s | Scope : %v", *decision.Value, *decision.Scenario, *decision.Duration, *decision.Scope)

	ipv6 := strings.Contains(*decision.Value, ":")

	if ipv6 && !useIPV6 {
		log.Info().Msgf("Ignore removing address %s (IPv6 disabled)", *decision.Value)
		return
	}

	if mal.blockedAddresses[ipv6][*decision.Value] {
		mal.modified = true
		delete(mal.blockedAddresses[ipv6], *decision.Value)
	} else {
		log.Warn().Msgf("%s not found in local cache", *decision.Value)
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

// reorderFirewallPolicies reorders the firewall policies according to the specified logic
func (mal *unifiAddrList) reorderFirewallPolicies(ctx context.Context) {
	log.Info().Msg("Starting firewall policy reordering")

	// Get all policies
	allPolicies, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get firewall policies for reordering")
		return
	}

	// Filter out predefined policies and policies from port forwarding with index 3XXXX
	var filteredPolicies []unifi.FirewallZonePolicy
	for _, policy := range allPolicies {
		if !policy.Predefined && (policy.Index < 30000 || policy.Index >= 40000) {
			filteredPolicies = append(filteredPolicies, policy)
		}
	}

	// Sort filtered policies by index to ensure consistent ordering
	sort.Slice(filteredPolicies, func(i, j int) bool {
		return filteredPolicies[i].Index < filteredPolicies[j].Index
	})

	// Iterate through each zone combination
	for _, zoneSrc := range unifiZoneSrc {
		for _, zoneDst := range unifiZoneDst {
			srcZoneId := mal.firewallZones[zoneSrc].id
			dstZoneId := mal.firewallZones[zoneDst].id

			// Filter policies for this specific zone combination
			var relevantPolicies []unifi.FirewallZonePolicy
			for _, policy := range filteredPolicies {
				// Check if policy belongs to the current zone combination
				if policy.Source.ZoneID == srcZoneId && policy.Destination.ZoneID == dstZoneId {
					relevantPolicies = append(relevantPolicies, policy)
				}
			}

			if len(relevantPolicies) == 0 {
				continue
			}

			// Separate policies into pre (index < 30000) and after (index >= 40000) lists
			var prePolicies []unifi.FirewallZonePolicy
			var afterPolicies []unifi.FirewallZonePolicy
			var newPolicies []unifi.FirewallZonePolicy

			for _, policy := range relevantPolicies {
				// Check if this is one of our newly generated policies not yet with index >= 40000
				isNewPolicy := false
				// Check both IPv4 and IPv6 caches
				_, existsIPv4 := mal.firewallZonePolicy[false][policy.Name]
				_, existsIPv6 := mal.firewallZonePolicy[true][policy.Name]
				isNewPolicy = (existsIPv4 || existsIPv6) && policy.Index < 40000

				if isNewPolicy {
					newPolicies = append(newPolicies, policy)
				} else if policy.Index < 40000 {
					prePolicies = append(prePolicies, policy)
				} else {
					afterPolicies = append(afterPolicies, policy)
				}
			}

			// If there are no new policies to reorder, skip this zone combination
			// This can happen if all policies are already in the correct order
			if len(newPolicies) == 0 {
				continue
			}

			// Initialize as empty slices (not nil) to ensure API compatibility
			beforePredefinedIds := make([]string, 0)
			afterPredefinedIds := make([]string, 0)

			// Extract IDs from bouncer policies FIRST (highest priority - deny rules)
			for _, policy := range newPolicies {
				beforePredefinedIds = append(beforePredefinedIds, policy.ID)
			}

			// Extract IDs from existing custom policies (after bouncer rules)
			for _, policy := range prePolicies {
				beforePredefinedIds = append(beforePredefinedIds, policy.ID)
			}

			// Extract IDs from remaining after policies
			for _, policy := range afterPolicies {
				afterPredefinedIds = append(afterPredefinedIds, policy.ID)
			}

			// Create the reorder request
			reorderUpdate := &unifi.FirewallPolicyOrderUpdate{
				SourceZoneId:        srcZoneId,
				DestinationZoneId:   dstZoneId,
				AfterPredefinedIds:  afterPredefinedIds,
				BeforePredefinedIds: beforePredefinedIds,
			}

			// Execute the reorder
			_, err := mal.c.ReorderFirewallPolicies(ctx, unifiSite, reorderUpdate)
			if err != nil {
				log.Error().Err(err).
					Str("srcZone", zoneSrc).
					Str("dstZone", zoneDst).
					Msg("Failed to reorder firewall policies")
			} else {
				log.Info().
					Str("srcZone", zoneSrc).
					Str("dstZone", zoneDst).
					Int("beforeCount", len(beforePredefinedIds)).
					Int("afterCount", len(afterPredefinedIds)).
					Msg("Successfully reordered firewall policies")
			}
		}
	}
}
