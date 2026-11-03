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
	mal.loadUnifiState(ctx)
}

func (mal *unifiAddrList) loadUnifiState(ctx context.Context) {
	c := mal.c
	var err error

	mal.memberGroup = map[bool]map[string]string{
		true:  make(map[string]string),
		false: make(map[string]string),
	}
	mal.firewallGroups = map[bool]map[string]*FirewallGroupCache{
		true:  make(map[string]*FirewallGroupCache),
		false: make(map[string]*FirewallGroupCache),
	}

	mal.firewallRule = map[bool]map[string]FirewallRuleCache{
		true:  make(map[string]FirewallRuleCache),
		false: make(map[string]FirewallRuleCache),
	}

	mal.firewallZonePolicy = map[bool]map[string]FirewallZonePolicyCache{
		true:  make(map[string]FirewallZonePolicyCache),
		false: make(map[string]FirewallZonePolicyCache),
	}

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
		if !strings.Contains(group.Name, "cs-unifi-bouncer") {
			continue
		}

		ipv6 := strings.Contains(group.Name, "ipv6")

		cached := &FirewallGroupCache{
			id:      group.ID,
			members: make(map[string]bool, len(group.GroupMembers)),
		}
		for _, member := range group.GroupMembers {
			if owner, exists := mal.memberGroup[ipv6][member]; exists && owner != group.Name {
				// An interrupted older repartition can leave the same address in
				// more than one group. Keep the first owner, drop the duplicate
				// here, and rewrite this group on the next reconcile.
				log.Warn().Msgf("Address %s present in both %s and %s; keeping %s", member, owner, group.Name, owner)
				cached.touched = true
				continue
			}
			cached.members[member] = true
			mal.memberGroup[ipv6][member] = group.Name
		}
		mal.firewallGroups[ipv6][group.Name] = cached
	}

	// Check if firewall rules exists
	rules, err := mal.c.ListFirewallRule(ctx, unifiSite)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to get firewall rules")
	}

	for _, rule := range rules {
		if strings.Contains(rule.Name, "cs-unifi-bouncer") {
			ipv6 := strings.Contains(rule.Name, "ipv6")

			mal.firewallRule[ipv6][rule.Name] = FirewallRuleCache{id: rule.ID, groupId: rule.SrcFirewallGroupIDs[0]}
		}
	}

	// Check if firewall policies exists, delete them to start fresh
	if mal.isZoneBased {
		policies, err := mal.c.ListFirewallZonePolicy(ctx, unifiSite)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to get firewall policies")
		}

		for _, policy := range policies {
			if strings.Contains(policy.Name, "cs-unifi-bouncer") {
				mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, policy.ID)
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

// groupIndex extracts the integer index encoded in a group or rule name of the
// form cs-unifi-bouncer-<ipversion>-<index>.
func groupIndex(name string) (int, bool) {
	parts := strings.Split(name, "-")
	if len(parts) < 5 {
		return 0, false
	}
	index, err := strconv.Atoi(parts[4])
	if err != nil {
		return 0, false
	}
	return index, true
}

func sortedMembers(members map[string]bool) []string {
	out := make([]string, 0, len(members))
	for member := range members {
		out = append(out, member)
	}
	sort.Strings(out)
	return out
}

// groupNamesSorted returns the group names for a family ordered by their encoded
// index, giving deterministic iteration regardless of Go's map ordering.
func (mal *unifiAddrList) groupNamesSorted(ipv6 bool) []string {
	names := make([]string, 0, len(mal.firewallGroups[ipv6]))
	for name := range mal.firewallGroups[ipv6] {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		left, _ := groupIndex(names[i])
		right, _ := groupIndex(names[j])
		return left < right
	})
	return names
}

// firstNonFullGroup returns the lowest-indexed group that still has room, or ""
// when every group is full (or none exist).
func (mal *unifiAddrList) firstNonFullGroup(ipv6 bool) string {
	for _, name := range mal.groupNamesSorted(ipv6) {
		group := mal.firewallGroups[ipv6][name]
		if group != nil && len(group.members) < maxGroupSize {
			return name
		}
	}
	return ""
}

// newGroupName returns a name for a new group using the lowest free index so
// indices stay compact; freed indices are reused.
func (mal *unifiAddrList) newGroupName(ipv6 bool) string {
	used := make(map[int]bool, len(mal.firewallGroups[ipv6]))
	for name := range mal.firewallGroups[ipv6] {
		if index, ok := groupIndex(name); ok {
			used[index] = true
		}
	}
	index := 0
	for used[index] {
		index++
	}

	ipVersionString := "ipv4"
	if ipv6 {
		ipVersionString = "ipv6"
	}
	return fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, index)
}

func (mal *unifiAddrList) isBlocked(ipv6 bool, address string) bool {
	_, exists := mal.memberGroup[ipv6][address]
	return exists
}

// activeDecisionCount returns the number of blocked addresses for one family.
// It backs the active_decisions metric without keeping a second membership set.
func (mal *unifiAddrList) activeDecisionCount(ipv6 bool) int {
	return len(mal.memberGroup[ipv6])
}

// placeMember assigns a newly blocked address to a group without touching the
// controller. It reuses an existing non-full group, or creates a new one when
// every group is full. The group is marked touched so the next reconciliation
// writes it and only it.
func (mal *unifiAddrList) placeMember(ipv6 bool, address string) {
	groupName := mal.firstNonFullGroup(ipv6)
	if groupName == "" {
		groupName = mal.newGroupName(ipv6)
		mal.firewallGroups[ipv6][groupName] = &FirewallGroupCache{members: make(map[string]bool)}
		log.Info().Msgf("Created new firewall group: %s", groupName)
	}

	group := mal.firewallGroups[ipv6][groupName]
	group.members[address] = true
	group.touched = true
	mal.memberGroup[ipv6][address] = groupName
}

// removeMember removes an address from its owning group. An emptied group is
// left for the reconciliation to delete from the controller.
func (mal *unifiAddrList) removeMember(ipv6 bool, address string) {
	groupName, exists := mal.memberGroup[ipv6][address]
	if !exists {
		return
	}
	delete(mal.memberGroup[ipv6], address)

	group := mal.firewallGroups[ipv6][groupName]
	if group == nil {
		return
	}
	delete(group.members, address)
	group.touched = true
}

// Function to update the firewall groups for one address family.
//
// Groups are reconciled incrementally: only groups whose membership changed
// since the last successful write are pushed to the controller. Groups are never
// repartitioned, so adding or removing one address touches at most the single
// group it belongs to (plus a create when every group is full, or a delete when
// a group becomes empty).
func (mal *unifiAddrList) updateFirewall(ctx context.Context, ipv6 bool) {

	if !mal.modified {
		log.Debug().Msg("No changes detected, skipping update")
		return
	}

	ipVersionString := "ipv4"
	if ipv6 {
		ipVersionString = "ipv6"
	}

	names := mal.groupNamesSorted(ipv6)
	log.Info().Msgf("Reconciling %d %s firewall group(s)", len(names), ipVersionString)

	var newPoliciesPosted bool

	for _, groupName := range names {
		group := mal.firewallGroups[ipv6][groupName]
		if group == nil {
			continue
		}

		index, ok := groupIndex(groupName)
		if !ok {
			log.Warn().Msgf("Invalid group index in name: %s", groupName)
			continue
		}

		// An emptied group is no longer needed.
		if len(group.members) == 0 {
			mal.deleteFirewallGroup(ctx, ipv6, groupName)
			continue
		}

		// Only push membership that actually changed (or a brand new group).
		groupID := group.id
		if groupID == "" || group.touched {
			groupID = mal.postFirewallGroup(ctx, groupID, groupName, ipv6, sortedMembers(group.members))
			if groupID == "" {
				// postFirewallGroup already logged the fatal error.
				continue
			}
			group.id = groupID
			group.touched = false
		}

		// Make sure the rule/policy that references this group exists and points
		// at the current group ID. This is a cheap cache check that only writes
		// when something is genuinely missing or stale.
		if mal.isZoneBased {
			for _, zoneSrc := range unifiZoneSrc {
				for _, zoneDst := range unifiZoneDst {
					policyName := fmt.Sprintf("cs-unifi-bouncer-%s-%s->%s-%d", ipVersionString, zoneSrc, zoneDst, index)
					policyId := ""
					cachedGroupId := ""
					if policyCache, exists := mal.firewallZonePolicy[ipv6][policyName]; exists {
						policyId = policyCache.id
						cachedGroupId = policyCache.groupId
					}
					if groupID != cachedGroupId {
						newPoliciesPosted = true
						mal.postFirewallPolicy(ctx, policyId, policyName, ipv6, groupID, index, zoneSrc, zoneDst)
					}
				}
			}
		} else {
			ruleName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionString, index)
			ruleId := ""
			cachedGroupId := ""
			if ruleCache, exists := mal.firewallRule[ipv6][ruleName]; exists {
				ruleId = ruleCache.id
				cachedGroupId = ruleCache.groupId
			}
			if groupID != cachedGroupId {
				mal.postFirewallRule(ctx, index, ruleId, ruleName, ipv6, groupID)
			}
		}
	}

	// Reorder policies after all have been generated (if enabled in config)
	if mal.isZoneBased && unifiPolicyReordering && (newPoliciesPosted || !mal.initialReorderingDone) {
		mal.initialReorderingDone = true
		mal.reorderFirewallPolicies(ctx)
	}

	// Remove rules/policies that no longer map to a managed group (e.g. groups
	// deleted while the bouncer was down, or out-of-scope zones).
	mal.deleteOrphanRulesAndPolicies(ctx, ipv6)
}

// deleteFirewallGroup removes a group that no longer has any members, along with
// the rules/policies that referenced it. If the controller delete fails the
// group is kept so the next reconciliation retries.
func (mal *unifiAddrList) deleteFirewallGroup(ctx context.Context, ipv6 bool, groupName string) {
	group := mal.firewallGroups[ipv6][groupName]
	if group == nil {
		return
	}

	index, _ := groupIndex(groupName)
	// UniFi refuses to delete a group while a rule/policy still references it, so
	// remove those first. If that fails, keep the group and retry next reconcile.
	if !mal.deleteGroupRulesAndPolicies(ctx, ipv6, index) {
		log.Warn().Msgf("Keeping firewall group %s: its rule/policy could not be deleted", groupName)
		return
	}

	if group.id != "" {
		if err := mal.c.DeleteFirewallGroup(ctx, unifiSite, group.id); err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall group: %s", groupName)
			return
		}
	}

	log.Info().Msgf("Deleted old firewall group: %s", groupName)
	delete(mal.firewallGroups[ipv6], groupName)
}

// deleteGroupRulesAndPolicies deletes every rule/policy that belongs to a group
// index, regardless of whether the group was zone-based. It reports whether all
// of them are gone; a caller must not delete the group while any remain, because
// UniFi refuses to remove a group that is still referenced.
func (mal *unifiAddrList) deleteGroupRulesAndPolicies(ctx context.Context, ipv6 bool, index int) bool {
	allDeleted := true

	if mal.isZoneBased {
		for policyName, policyCache := range mal.firewallZonePolicy[ipv6] {
			if policyCache.index != index {
				continue
			}
			if err := mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, policyCache.id); err != nil {
				log.Error().Err(err).Msgf("Failed to delete old firewall policy: %s", policyName)
				allDeleted = false
			} else {
				log.Info().Msgf("Deleted old firewall policy: %s", policyName)
				delete(mal.firewallZonePolicy[ipv6], policyName)
			}
		}
	}

	// A classic rule can still reference this group: in non-zone mode, or left
	// over from a classic configuration after switching to zone-based mode.
	ruleName := fmt.Sprintf("cs-unifi-bouncer-%s-%d", ipVersionStringFor(ipv6), index)
	if ruleCache, exists := mal.firewallRule[ipv6][ruleName]; exists {
		if err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id); err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", ruleName)
			allDeleted = false
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", ruleName)
			delete(mal.firewallRule[ipv6], ruleName)
		}
	}

	return allDeleted
}

// deleteOrphanRulesAndPolicies removes cached rules/policies whose group index no
// longer exists, or whose zones are out of scope.
func (mal *unifiAddrList) deleteOrphanRulesAndPolicies(ctx context.Context, ipv6 bool) {
	existing := make(map[int]bool, len(mal.firewallGroups[ipv6]))
	for name := range mal.firewallGroups[ipv6] {
		if index, ok := groupIndex(name); ok {
			existing[index] = true
		}
	}

	for ruleName, ruleCache := range mal.firewallRule[ipv6] {
		index, ok := groupIndex(ruleName)
		// Classic rules are obsolete in zone-based mode and must not survive a
		// switch from classic to zone.
		if !mal.isZoneBased && ok && existing[index] {
			continue
		}
		if err := mal.c.DeleteFirewallRule(ctx, unifiSite, ruleCache.id); err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall rule: %s", ruleName)
		} else {
			log.Info().Msgf("Deleted old firewall rule: %s", ruleName)
			delete(mal.firewallRule[ipv6], ruleName)
		}
	}

	for policyName, policyCache := range mal.firewallZonePolicy[ipv6] {
		if existing[policyCache.index] && slices.Contains(unifiZoneSrc, policyCache.zoneSrc) && slices.Contains(unifiZoneDst, policyCache.zoneDst) {
			continue
		}
		if err := mal.c.DeleteFirewallZonePolicy(ctx, unifiSite, policyCache.id); err != nil {
			log.Error().Err(err).Msgf("Failed to delete old firewall policy: %s", policyName)
		} else {
			log.Info().Msgf("Deleted old firewall policy: %s", policyName)
			delete(mal.firewallZonePolicy[ipv6], policyName)
		}
	}
}

func ipVersionStringFor(ipv6 bool) string {
	if ipv6 {
		return "ipv6"
	}
	return "ipv4"
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

	if mal.isBlocked(ipv6, *decision.Value) {
		log.Warn().Msgf("Address %s already present", *decision.Value)
	} else {
		mal.modified = true
		mal.placeMember(ipv6, *decision.Value)
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

	if mal.isBlocked(ipv6, *decision.Value) {
		mal.modified = true
		mal.removeMember(ipv6, *decision.Value)
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
