package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type fakeUnifi struct {
	unifi.Client
	groups    map[string]unifi.FirewallGroup
	rules     map[string]unifi.FirewallRule
	policies  map[string]unifi.FirewallZonePolicy
	zones     []unifi.FirewallZone
	zoneBased bool

	groupCreates  int
	groupUpdates  int
	groupDeletes  int
	ruleCreates   int
	ruleUpdates   int
	ruleDeletes   int
	policyCreates int
	policyUpdates int
	policyDeletes int
	reorders      int

	writeErr error
	nextID   int
}

func newFakeUnifi() *fakeUnifi {
	return &fakeUnifi{
		groups:   make(map[string]unifi.FirewallGroup),
		rules:    make(map[string]unifi.FirewallRule),
		policies: make(map[string]unifi.FirewallZonePolicy),
	}
}

func (f *fakeUnifi) resetCounts() {
	f.groupCreates, f.groupUpdates, f.groupDeletes = 0, 0, 0
	f.ruleCreates, f.ruleUpdates, f.ruleDeletes = 0, 0, 0
	f.policyCreates, f.policyUpdates, f.policyDeletes = 0, 0, 0
	f.reorders = 0
}

func (f *fakeUnifi) groupWrites() int { return f.groupCreates + f.groupUpdates }

func cloneGroup(g unifi.FirewallGroup) unifi.FirewallGroup {
	g.GroupMembers = slices.Clone(g.GroupMembers)
	return g
}

func (f *fakeUnifi) IsFeatureEnabled(context.Context, string, string) (bool, error) {
	return f.zoneBased, nil
}

func (f *fakeUnifi) ListFirewallGroup(context.Context, string) ([]unifi.FirewallGroup, error) {
	out := make([]unifi.FirewallGroup, 0, len(f.groups))
	for _, g := range f.groups {
		out = append(out, cloneGroup(g))
	}
	return out, nil
}

func (f *fakeUnifi) CreateFirewallGroup(_ context.Context, _ string, g *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	f.groupCreates++
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	f.nextID++
	created := cloneGroup(*g)
	created.ID = fmt.Sprintf("group-%d", f.nextID)
	f.groups[created.Name] = created
	return &created, nil
}

func (f *fakeUnifi) UpdateFirewallGroup(_ context.Context, _ string, g *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	f.groupUpdates++
	if f.writeErr != nil && !errors.Is(f.writeErr, unifi.ErrNotFound) {
		return nil, f.writeErr
	}
	if f.writeErr == nil {
		f.groups[g.Name] = cloneGroup(*g)
	}
	return nil, f.writeErr
}

func (f *fakeUnifi) DeleteFirewallGroup(_ context.Context, _ string, id string) error {
	for name, g := range f.groups {
		if g.ID == id {
			f.groupDeletes++
			delete(f.groups, name)
			return nil
		}
	}
	return nil
}

func (f *fakeUnifi) ListFirewallRule(context.Context, string) ([]unifi.FirewallRule, error) {
	out := make([]unifi.FirewallRule, 0, len(f.rules))
	for _, r := range f.rules {
		out = append(out, r)
	}
	return out, nil
}

func (f *fakeUnifi) CreateFirewallRule(_ context.Context, _ string, r *unifi.FirewallRule) (*unifi.FirewallRule, error) {
	f.ruleCreates++
	created := *r
	created.ID = "rule-" + r.Name
	f.rules[created.Name] = created
	return &created, nil
}

func (f *fakeUnifi) UpdateFirewallRule(_ context.Context, _ string, r *unifi.FirewallRule) (*unifi.FirewallRule, error) {
	f.ruleUpdates++
	updated := *r
	f.rules[updated.Name] = updated
	return &updated, nil
}

func (f *fakeUnifi) DeleteFirewallRule(_ context.Context, _ string, id string) error {
	for name, r := range f.rules {
		if r.ID == id {
			f.ruleDeletes++
			delete(f.rules, name)
		}
	}
	return nil
}

func (f *fakeUnifi) ListFirewallZone(context.Context, string) ([]unifi.FirewallZone, error) {
	return slices.Clone(f.zones), nil
}

func (f *fakeUnifi) ListFirewallZonePolicy(context.Context, string) ([]unifi.FirewallZonePolicy, error) {
	out := make([]unifi.FirewallZonePolicy, 0, len(f.policies))
	for _, p := range f.policies {
		out = append(out, p)
	}
	return out, nil
}

func (f *fakeUnifi) CreateFirewallZonePolicy(_ context.Context, _ string, p *unifi.FirewallZonePolicy) (*unifi.FirewallZonePolicy, error) {
	f.policyCreates++
	created := *p
	created.ID = "policy-" + p.Name
	f.policies[created.Name] = created
	return &created, nil
}

func (f *fakeUnifi) UpdateFirewallZonePolicy(_ context.Context, _ string, p *unifi.FirewallZonePolicy) (*unifi.FirewallZonePolicy, error) {
	f.policyUpdates++
	updated := *p
	f.policies[updated.Name] = updated
	return &updated, nil
}

func (f *fakeUnifi) DeleteFirewallZonePolicy(_ context.Context, _ string, id string) error {
	for name, p := range f.policies {
		if p.ID == id {
			f.policyDeletes++
			delete(f.policies, name)
		}
	}
	return nil
}

func (f *fakeUnifi) ReorderFirewallPolicies(context.Context, string, *unifi.FirewallPolicyOrderUpdate) ([]unifi.FirewallZonePolicy, error) {
	f.reorders++
	return nil, nil
}

func testSettings(t *testing.T, size int) {
	t.Helper()
	oldSize, oldSite, oldIPv6, oldLogger := maxGroupSize, unifiSite, useIPV6, log.Logger
	oldSrc, oldDst, oldReorder := unifiZoneSrc, unifiZoneDst, unifiPolicyReordering
	oldV4, oldV6 := ipv4StartRuleIndex, ipv6StartRuleIndex
	maxGroupSize, unifiSite = size, "test"
	useIPV6 = true
	unifiZoneSrc, unifiZoneDst, unifiPolicyReordering = nil, nil, false
	ipv4StartRuleIndex, ipv6StartRuleIndex = 0, 0
	log.Logger = zerolog.Nop()
	t.Cleanup(func() {
		maxGroupSize, unifiSite, useIPV6, log.Logger = oldSize, oldSite, oldIPv6, oldLogger
		unifiZoneSrc, unifiZoneDst, unifiPolicyReordering = oldSrc, oldDst, oldReorder
		ipv4StartRuleIndex, ipv6StartRuleIndex = oldV4, oldV6
	})
}

func loadTestState(f *fakeUnifi) *unifiAddrList {
	mal := &unifiAddrList{c: f}
	mal.loadUnifiState(context.Background())
	mal.modified = true
	return mal
}

func addressesFor(count int) []string {
	out := make([]string, count)
	for i := range out {
		out[i] = fmt.Sprintf("10.0.%d.%d", i/256, i%256)
	}
	return out
}

func decision(value string) *models.Decision {
	kind, origin, scenario, duration, scope := "ban", "cscli", "test", "1h", "Ip"
	return &models.Decision{Type: &kind, Value: &value, Origin: &origin, Scenario: &scenario, Duration: &duration, Scope: &scope}
}

func flush(mal *unifiAddrList, ipv6 bool) {
	mal.updateFirewall(context.Background(), ipv6)
	mal.modified = false
}

func groupMembersByName(f *fakeUnifi, name string) []string {
	g, ok := f.groups[name]
	if !ok {
		return nil
	}
	return slices.Clone(g.GroupMembers)
}

func sortedGroupNames(f *fakeUnifi) []string {
	names := make([]string, 0, len(f.groups))
	for name := range f.groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func totalMembers(f *fakeUnifi) int {
	total := 0
	for _, g := range f.groups {
		total += len(g.GroupMembers)
	}
	return total
}

// A new address goes into an existing group that still has room; only that one
// group is written, and no new group is created.
func TestAddFillsExistingGroupBeforeCreatingNew(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	for _, addr := range addressesFor(2) {
		mal.add(decision(addr))
	}
	flush(mal, false)
	if len(f.groups) != 1 || f.groupCreates != 1 {
		t.Fatalf("setup: groups=%d creates=%d, want 1/1", len(f.groups), f.groupCreates)
	}

	f.resetCounts()
	mal.add(decision(addressesFor(3)[2]))
	flush(mal, false)

	if len(f.groups) != 1 {
		t.Fatalf("groups=%d, want 1 (no new group)", len(f.groups))
	}
	if f.groupUpdates != 1 || f.groupCreates != 0 {
		t.Fatalf("group creates/updates=%d/%d, want 0/1", f.groupCreates, f.groupUpdates)
	}
	if totalMembers(f) != 3 {
		t.Fatalf("total members=%d, want 3", totalMembers(f))
	}
}

// When every group is full a new group is created; only the new group (and no
// existing group) is written.
func TestCreateNewGroupOnlyWhenAllFull(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	for _, addr := range addressesFor(6) {
		mal.add(decision(addr))
	}
	flush(mal, false)
	if len(f.groups) != 2 {
		t.Fatalf("groups=%d, want 2", len(f.groups))
	}

	f.resetCounts()
	mal.add(decision(addressesFor(7)[6]))
	flush(mal, false)

	if len(f.groups) != 3 {
		t.Fatalf("groups=%d, want 3", len(f.groups))
	}
	if f.groupCreates != 1 || f.groupUpdates != 0 {
		t.Fatalf("group creates/updates=%d/%d, want 1/0", f.groupCreates, f.groupUpdates)
	}
}

// The key win over sort-and-slice: removing one address from the middle rewrites
// only the group that owns it, not every group after it.
func TestRemoveTouchesOnlyOwningGroup(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	addresses := addressesFor(9)
	for _, addr := range addresses {
		mal.add(decision(addr))
	}
	flush(mal, false)
	if len(f.groups) != 3 {
		t.Fatalf("groups=%d, want 3", len(f.groups))
	}
	before := map[string][]string{}
	for _, name := range sortedGroupNames(f) {
		before[name] = groupMembersByName(f, name)
	}

	f.resetCounts()
	// addresses[4] lives in the middle group (index 1).
	mal.remove(decision(addresses[4]))
	flush(mal, false)

	if f.groupWrites() != 1 {
		t.Fatalf("group writes=%d, want exactly 1 (no cascade)", f.groupWrites())
	}
	if f.groupDeletes != 0 {
		t.Fatalf("group deletes=%d, want 0", f.groupDeletes)
	}
	// The other two groups must be byte-for-byte untouched.
	names := sortedGroupNames(f)
	if !slices.Equal(groupMembersByName(f, names[0]), before[names[0]]) {
		t.Fatal("lower group was rewritten")
	}
	if !slices.Equal(groupMembersByName(f, names[2]), before[names[2]]) {
		t.Fatal("higher group was rewritten")
	}
	if totalMembers(f) != 8 {
		t.Fatalf("total members=%d, want 8", totalMembers(f))
	}
}

func TestEmptiedGroupIsDeleted(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	addresses := addressesFor(3)
	for _, addr := range addresses {
		mal.add(decision(addr))
	}
	flush(mal, false)
	f.resetCounts()

	for _, addr := range addresses {
		mal.remove(decision(addr))
	}
	flush(mal, false)

	if f.groupDeletes != 1 {
		t.Fatalf("group deletes=%d, want 1", f.groupDeletes)
	}
	if f.groupWrites() != 0 {
		t.Fatalf("group writes=%d, want 0", f.groupWrites())
	}
	if len(f.groups) != 0 {
		t.Fatalf("groups=%d, want 0", len(f.groups))
	}
	if f.ruleDeletes != 1 {
		t.Fatalf("rule deletes=%d, want 1", f.ruleDeletes)
	}
}

func TestUnchangedReconcileWritesNothing(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	for _, addr := range addressesFor(7) {
		mal.add(decision(addr))
	}
	flush(mal, false)
	f.resetCounts()

	mal.modified = true
	flush(mal, false)

	if f.groupWrites() != 0 || f.ruleCreates != 0 || f.ruleUpdates != 0 || f.groupDeletes != 0 {
		t.Fatalf("unchanged reconcile wrote something: groups=%d rules=%d/%d deletes=%d",
			f.groupWrites(), f.ruleCreates, f.ruleUpdates, f.groupDeletes)
	}
}

// A restart that reloads the groups and rules from the controller writes nothing
// when the desired set is unchanged.
func TestRestartWritesNothing(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)
	for _, addr := range addressesFor(7) {
		mal.add(decision(addr))
	}
	flush(mal, false)

	f.resetCounts()
	restarted := loadTestState(f)
	for _, addr := range addressesFor(7) {
		restarted.add(decision(addr)) // stream replays existing decisions
	}
	flush(restarted, false)

	if f.groupWrites() != 0 || f.ruleCreates != 0 || f.ruleUpdates != 0 {
		t.Fatalf("restart wrote something: groups=%d rules=%d/%d",
			f.groupWrites(), f.ruleCreates, f.ruleUpdates)
	}
}

func TestZoneBasedCreatesOnePolicyPerGroup(t *testing.T) {
	testSettings(t, 3)
	unifiZoneSrc = []string{"External"}
	unifiZoneDst = []string{"Internal"}

	f := newFakeUnifi()
	f.zoneBased = true
	f.zones = []unifi.FirewallZone{{ID: "z-ext", Name: "External"}, {ID: "z-int", Name: "Internal"}}
	mal := loadTestState(f)

	for _, addr := range addressesFor(6) {
		mal.add(decision(addr))
	}
	flush(mal, false)

	if len(f.groups) != 2 {
		t.Fatalf("groups=%d, want 2", len(f.groups))
	}
	if f.policyCreates != 2 {
		t.Fatalf("policy creates=%d, want 2 (one per group)", f.policyCreates)
	}
}

// Adding to an existing (non-full) group in zone mode rewrites the group but not
// its policy, because the policy only references the (unchanged) group ID.
func TestZoneAddIntoExistingGroupDoesNotRewritePolicy(t *testing.T) {
	testSettings(t, 3)
	unifiZoneSrc = []string{"External"}
	unifiZoneDst = []string{"Internal"}

	f := newFakeUnifi()
	f.zoneBased = true
	f.zones = []unifi.FirewallZone{{ID: "z-ext", Name: "External"}, {ID: "z-int", Name: "Internal"}}
	mal := loadTestState(f)

	// 5 addresses => group 0 full (3), group 1 partial (2).
	for _, addr := range addressesFor(5) {
		mal.add(decision(addr))
	}
	flush(mal, false)
	if f.policyCreates != 2 {
		t.Fatalf("setup policy creates=%d, want 2", f.policyCreates)
	}

	f.resetCounts()
	mal.add(decision(addressesFor(6)[5]))
	flush(mal, false)

	if f.groupUpdates != 1 || f.groupCreates != 0 {
		t.Fatalf("group creates/updates=%d/%d, want 0/1", f.groupCreates, f.groupUpdates)
	}
	if f.policyCreates != 0 || f.policyUpdates != 0 {
		t.Fatalf("policy writes=%d/%d, want 0/0", f.policyCreates, f.policyUpdates)
	}
}

func TestZoneEmptiedGroupDeletesPolicy(t *testing.T) {
	testSettings(t, 3)
	unifiZoneSrc = []string{"External"}
	unifiZoneDst = []string{"Internal"}

	f := newFakeUnifi()
	f.zoneBased = true
	f.zones = []unifi.FirewallZone{{ID: "z-ext", Name: "External"}, {ID: "z-int", Name: "Internal"}}
	mal := loadTestState(f)

	addresses := addressesFor(3)
	for _, addr := range addresses {
		mal.add(decision(addr))
	}
	flush(mal, false)
	f.resetCounts()

	for _, addr := range addresses {
		mal.remove(decision(addr))
	}
	flush(mal, false)

	if f.groupDeletes != 1 {
		t.Fatalf("group deletes=%d, want 1", f.groupDeletes)
	}
	if f.policyDeletes != 1 {
		t.Fatalf("policy deletes=%d, want 1", f.policyDeletes)
	}
}

// Endpoints of the address range should still land in a group and never exceed
// maxGroupSize.
func TestGroupsNeverExceedMaxSize(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)

	for _, addr := range addressesFor(10) {
		mal.add(decision(addr))
	}
	flush(mal, false)

	for name, g := range f.groups {
		if len(g.GroupMembers) == 0 || len(g.GroupMembers) > maxGroupSize {
			t.Fatalf("group %s has %d members (max %d)", name, len(g.GroupMembers), maxGroupSize)
		}
	}
	if totalMembers(f) != 10 {
		t.Fatalf("total members=%d, want 10", totalMembers(f))
	}
}
