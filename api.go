package main

import (
	"context"
	"errors"
	"strings"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

// withUniFiReauthRetry retries a failed UniFi write once after reauthenticating on HTTP 401.
func (mal *unifiAddrList) withUniFiReauthRetry(resourceType, resourceName string, operation func() error) error {
	err := operation()
	if err == nil || !strings.Contains(err.Error(), "Server error (401)") {
		return err
	}

	log.Warn().Err(err).Str("type", resourceType).Str("name", resourceName).Msg("UniFi session unauthorized; reconnecting and retrying once")
	refreshed, authErr := dial()
	if authErr != nil {
		log.Error().Err(authErr).Str("type", resourceType).Str("name", resourceName).Msg("UniFi reauthentication failed")
		return err
	}
	mal.c = refreshed

	err = operation()
	if err == nil {
		log.Info().Str("type", resourceType).Str("name", resourceName).Msg("UniFi reauthentication and retry succeeded")
	}
	return err
}

// postFirewallRule creates or updates a firewall rule in the UniFi controller.
// The rule will drop all traffic from the specified source firewall group IDs.
//
// Parameters:
// - ctx: The context for the request.
// - index: An integer used to generate the rule name and differentiate between rules.
// - ID: The ID of the firewall rule to update. If empty, a new rule will be created.
// - ipv6: A boolean indicating whether the rule is for IPv6 traffic.
// - groupIds: A slice of strings containing the source firewall group IDs.
//
// The function constructs a firewall rule with the specified parameters and either
// updates an existing rule or creates a new one in the UniFi controller. If the
// operation fails, it logs a fatal error. Otherwise, it logs an informational message.
func (mal *unifiAddrList) postFirewallRule(ctx context.Context, index int, ID string, ruleName string, ipv6 bool, groupId string) {
	ruleset := "WAN_IN"
	if ipv6 {
		ruleset = "WANv6_IN"
	}

	startRuleIndex := ipv4StartRuleIndex
	if ipv6 {
		startRuleIndex = ipv6StartRuleIndex
	}

	firewallRule := &unifi.FirewallRule{
		Action:              "drop",
		Enabled:             true,
		Name:                ruleName,
		SrcFirewallGroupIDs: []string{groupId},
		Protocol:            "all",
		Ruleset:             ruleset,
		SettingPreference:   "auto",
		RuleIndex:           startRuleIndex + index,
		Logging:             unifiLogging,
	}

	if !ipv6 {
		firewallRule.SrcNetworkType = "NETv4"
		firewallRule.DstNetworkType = "NETv4"
	}

	var err error
	var newFirewallRule *unifi.FirewallRule

	err = mal.withUniFiReauthRetry("firewall rule", ruleName, func() error {
		if ID != "" {
			firewallRule.ID = ID
			_, updateErr := mal.c.UpdateFirewallRule(ctx, unifiSite, firewallRule)
			return updateErr
		}
		var createErr error
		newFirewallRule, createErr = mal.c.CreateFirewallRule(ctx, unifiSite, firewallRule)
		return createErr
	})

	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to post firewall rule: %v", firewallRule)
	} else {
		if newFirewallRule != nil {
			firewallRule = newFirewallRule
		}
		log.Info().Msg("Firewall rule posted")
		mal.firewallRule[ipv6][firewallRule.Name] = FirewallRuleCache{id: firewallRule.ID, groupId: groupId}
	}
}

func (mal *unifiAddrList) postFirewallPolicy(ctx context.Context, ID string, policyName string, ipv6 bool, groupId string, srcZone string, dstZone string) {
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}

	srcZoneId := mal.firewallZones[srcZone].id
	dstZoneId := mal.firewallZones[dstZone].id

	firewallZonePolicy := &unifi.FirewallZonePolicy{
		Action:              "BLOCK",
		Enabled:             true,
		Name:                policyName,
		ConnectionStateType: "CUSTOM",
		ConnectionStates:  []string{"NEW", "INVALID"},
		Protocol:            "all",
		IPVersion:           ipVersion,
		Logging:             unifiLogging,
		Description:         "Automatically added by the cs-unifi-bouncer",
		Source: unifi.FirewallZonePolicySource{
			ZoneID:             srcZoneId,
			MatchingTarget:     "IP",
			MatchingTargetType: "OBJECT",
			PortMatchingType:   "ANY",
			IPGroupID:          groupId,
		},
		Destination: unifi.FirewallZonePolicyDestination{
			ZoneID:           dstZoneId,
			MatchingTarget:   "ANY",
			PortMatchingType: "ANY",
		},
		Schedule: unifi.FirewallZonePolicySchedule{
			Mode: "ALWAYS",
		},
	}

	var err error
	var newFirewallZonePolicy *unifi.FirewallZonePolicy

	err = mal.withUniFiReauthRetry("firewall policy", policyName, func() error {
		if ID != "" {
			firewallZonePolicy.ID = ID
			_, updateErr := mal.c.UpdateFirewallZonePolicy(ctx, unifiSite, firewallZonePolicy)
			return updateErr
		}
		var createErr error
		newFirewallZonePolicy, createErr = mal.c.CreateFirewallZonePolicy(ctx, unifiSite, firewallZonePolicy)
		return createErr
	})

	if err != nil {
		log.Fatal().Err(err).Msgf("Failed to post firewall policy: %v", firewallZonePolicy)
	} else {
		if newFirewallZonePolicy != nil {
			firewallZonePolicy = newFirewallZonePolicy
		}
		log.Info().Msg("Firewall policy posted")
		var firewallZonePolicyCache = FirewallZonePolicyCache{id: firewallZonePolicy.ID, groupId: groupId}
		mal.firewallZonePolicy[ipv6][firewallZonePolicy.Name] = firewallZonePolicyCache
	}
}

// postFirewallGroup creates or updates a firewall group in the UniFi controller.
// It constructs the group name and type based on the provided parameters and
// either updates an existing group if an ID is provided or creates a new one.
//
// Parameters:
// - ctx: The context for the request.
// - index: An integer used to generate the group name and differentiate between groups.
// - ID: The ID of the firewall group to update. If empty, a new group will be created.
// - ipv6: A boolean indicating whether the group is for IPv6 addresses.
// - members: A slice of strings representing the members of the firewall group.
//
// The function logs a fatal error if the operation fails, otherwise it logs a success message.
func (mal *unifiAddrList) postFirewallGroup(ctx context.Context, ID string, groupName string, ipv6 bool, members []string) string {
	groupType := "address-group"
	if ipv6 {
		groupType = "ipv6-address-group"
	}

	group := &unifi.FirewallGroup{
		Name:         groupName,
		GroupType:    groupType,
		GroupMembers: members,
	}

	var err error
	var newGroup *unifi.FirewallGroup

	err = mal.withUniFiReauthRetry("firewall group", groupName, func() error {
		if ID != "" {
			group.ID = ID
			_, updateErr := mal.c.UpdateFirewallGroup(ctx, unifiSite, group)
			return updateErr
		}
		var createErr error
		newGroup, createErr = mal.c.CreateFirewallGroup(ctx, unifiSite, group)
		return createErr
	})

	if err != nil {
		// If updating and got "not found", it means no changes were needed (UniFi returns empty data)
		if ID != "" && errors.Is(err, unifi.ErrNotFound) {
			log.Debug().Msgf("No update needed for firewall group: %s", groupName)
			mal.firewallGroups[ipv6][group.Name] = group.ID
			return group.ID
		}
		log.Fatal().Err(err).Str("group", groupName).Msg("Failed to post firewall group")
		return ""
	} else {
		if newGroup != nil {
			group = newGroup
		}
		log.Info().Msg("Firewall group posted")
		mal.firewallGroups[ipv6][group.Name] = group.ID
		return group.ID
	}
}
