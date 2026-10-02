package main

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
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
	groups   map[string]unifi.FirewallGroup
	rules    map[string]unifi.FirewallRule
	writes   []unifi.FirewallGroup
	deleted  []string
	writeErr error
	nextID   int
}

func newFakeUnifi() *fakeUnifi {
	return &fakeUnifi{groups: make(map[string]unifi.FirewallGroup), rules: make(map[string]unifi.FirewallRule)}
}

func cloneGroup(g unifi.FirewallGroup) unifi.FirewallGroup {
	g.GroupMembers = slices.Clone(g.GroupMembers)
	return g
}

func (f *fakeUnifi) IsFeatureEnabled(context.Context, string, string) (bool, error) {
	return false, nil
}

func (f *fakeUnifi) ListFirewallGroup(context.Context, string) ([]unifi.FirewallGroup, error) {
	var groups []unifi.FirewallGroup
	for _, g := range f.groups {
		groups = append(groups, cloneGroup(g))
	}
	return groups, nil
}

func (f *fakeUnifi) ListFirewallRule(context.Context, string) ([]unifi.FirewallRule, error) {
	var rules []unifi.FirewallRule
	for _, r := range f.rules {
		rules = append(rules, r)
	}
	return rules, nil
}

func (f *fakeUnifi) CreateFirewallGroup(_ context.Context, _ string, g *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	f.writes = append(f.writes, cloneGroup(*g))
	if f.writeErr != nil {
		return nil, f.writeErr
	}
	f.nextID++
	created := cloneGroup(*g)
	created.ID = fmt.Sprintf("group-%d", f.nextID)
	f.groups[g.Name] = created
	return &created, nil
}

func (f *fakeUnifi) UpdateFirewallGroup(_ context.Context, _ string, g *unifi.FirewallGroup) (*unifi.FirewallGroup, error) {
	f.writes = append(f.writes, cloneGroup(*g))
	if f.writeErr != nil && !errors.Is(f.writeErr, unifi.ErrNotFound) {
		return nil, f.writeErr
	}
	f.groups[g.Name] = cloneGroup(*g)
	return nil, f.writeErr
}

func (f *fakeUnifi) CreateFirewallRule(_ context.Context, _ string, r *unifi.FirewallRule) (*unifi.FirewallRule, error) {
	created := *r
	created.ID = "rule-" + r.Name
	f.rules[r.Name] = created
	return &created, nil
}

func (f *fakeUnifi) DeleteFirewallRule(_ context.Context, _ string, id string) error {
	for name, r := range f.rules {
		if r.ID == id {
			delete(f.rules, name)
		}
	}
	return nil
}

func (f *fakeUnifi) DeleteFirewallGroup(_ context.Context, _ string, id string) error {
	for name, g := range f.groups {
		if g.ID == id {
			f.deleted = append(f.deleted, name)
			delete(f.groups, name)
		}
	}
	return nil
}

func testSettings(t *testing.T, size int) {
	t.Helper()
	oldSize, oldSite, oldIPv6, oldLogger := maxGroupSize, unifiSite, useIPV6, log.Logger
	maxGroupSize, unifiSite = size, "test"
	useIPV6 = true
	log.Logger = zerolog.Nop()
	t.Cleanup(func() { maxGroupSize, unifiSite, useIPV6, log.Logger = oldSize, oldSite, oldIPv6, oldLogger })
}

func loadTestState(f *fakeUnifi) *unifiAddrList {
	mal := &unifiAddrList{c: f}
	mal.loadUnifiState(context.Background())
	mal.modified = true
	return mal
}

func addressesFor(ipv6 bool, count int) []string {
	addresses := make([]string, count)
	for i := range addresses {
		if ipv6 {
			addresses[i] = fmt.Sprintf("2001:db8::%04x", i+1)
		} else {
			addresses[i] = fmt.Sprintf("10.%d.%d.%d", i/65536, i/256%256, i%256)
		}
	}
	return addresses
}

func memberships(f *fakeUnifi) map[string][]string {
	result := make(map[string][]string)
	for name, g := range f.groups {
		result[name] = slices.Clone(g.GroupMembers)
	}
	return result
}

func assertBlocklist(t *testing.T, f *fakeUnifi, want []string, ipv6 bool, size int) {
	t.Helper()
	typeName := "address-group"
	if ipv6 {
		typeName = "ipv6-address-group"
	}
	var actual []string
	for _, g := range f.groups {
		if len(g.GroupMembers) > size || len(g.GroupMembers) == 0 {
			t.Fatalf("invalid group size: %d", len(g.GroupMembers))
		}
		if g.GroupType != typeName {
			t.Fatalf("group type = %s, want %s", g.GroupType, typeName)
		}
		actual = append(actual, g.GroupMembers...)
	}
	sort.Strings(actual)
	want = slices.Clone(want)
	sort.Strings(want)
	if !slices.Equal(actual, want) {
		t.Fatalf("blocklist differs: got %d members, want %d", len(actual), len(want))
	}
}

func TestDeterministicGrouping(t *testing.T) {
	testSettings(t, 10000)
	for _, ipv6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv6=%t", ipv6), func(t *testing.T) {
			addresses := addressesFor(ipv6, 25001)
			var expected map[string][]string
			for seed := int64(0); seed < 5; seed++ {
				f := newFakeUnifi()
				mal := loadTestState(f)
				order := slices.Clone(addresses)
				rand.New(rand.NewSource(seed)).Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
				for _, addr := range order {
					mal.blockedAddresses[ipv6][addr] = true
				}
				mal.updateFirewall(context.Background(), ipv6)
				assertBlocklist(t, f, addresses, ipv6, maxGroupSize)
				if len(f.groups) != 3 {
					t.Fatalf("got %d groups, want 3", len(f.groups))
				}
				if expected == nil {
					expected = memberships(f)
				} else if !reflect.DeepEqual(memberships(f), expected) {
					t.Fatal("map insertion order changed group membership")
				}
				f.writes = nil
				for i := 0; i < 10; i++ {
					mal.updateFirewall(context.Background(), ipv6)
				}
				if len(f.writes) != 0 {
					t.Fatalf("unchanged reconciliations made %d group writes", len(f.writes))
				}
			}
		})
	}
}

func TestRestartSkipsUnchangedGroups(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)
	for _, ipv6 := range []bool{false, true} {
		for _, addr := range addressesFor(ipv6, 7) {
			mal.blockedAddresses[ipv6][addr] = true
		}
		mal.updateFirewall(context.Background(), ipv6)
	}
	// Controller responses need not order members the same way as the bouncer.
	for name, g := range f.groups {
		slices.Reverse(g.GroupMembers)
		f.groups[name] = g
	}
	before := memberships(f)
	f.writes = nil
	restarted := loadTestState(f)
	for _, ipv6 := range []bool{false, true} {
		restarted.updateFirewall(context.Background(), ipv6)
	}
	if len(f.writes) != 0 || !reflect.DeepEqual(before, memberships(f)) {
		t.Fatal("restart rewrote unchanged controller groups")
	}
}

func TestGroupSizeBoundaries(t *testing.T) {
	testSettings(t, 3)
	for _, ipv6 := range []bool{false, true} {
		for _, count := range []int{0, 1, 3, 4, 6, 7} {
			t.Run(fmt.Sprintf("ipv6=%t/count=%d", ipv6, count), func(t *testing.T) {
				f := newFakeUnifi()
				mal := loadTestState(f)
				addresses := addressesFor(ipv6, count)
				for _, addr := range addresses {
					mal.blockedAddresses[ipv6][addr] = true
				}
				mal.updateFirewall(context.Background(), ipv6)
				assertBlocklist(t, f, addresses, ipv6, maxGroupSize)
				if len(f.groups) != (count+2)/3 {
					t.Fatalf("unexpected number of groups: %d", len(f.groups))
				}
			})
		}
	}
}

func decision(value string) *models.Decision {
	kind, origin, scenario, duration, scope := "ban", "cscli", "test", "1h", "Ip"
	return &models.Decision{Type: &kind, Value: &value, Origin: &origin, Scenario: &scenario, Duration: &duration, Scope: &scope}
}

func TestMembershipChanges(t *testing.T) {
	testSettings(t, 3)
	for _, ipv6 := range []bool{false, true} {
		for _, change := range []string{"add-last", "remove-last", "add-first", "remove-first", "remove-all"} {
			t.Run(fmt.Sprintf("ipv6=%t/%s", ipv6, change), func(t *testing.T) {
				f := newFakeUnifi()
				mal := loadTestState(f)
				addresses := addressesFor(ipv6, 7)
				for _, addr := range addresses {
					mal.add(decision(addr))
				}
				mal.updateFirewall(context.Background(), ipv6)
				before := memberships(f)
				f.writes, f.deleted = nil, nil
				sorted := slices.Clone(addresses)
				sort.Strings(sorted)
				want := slices.Clone(sorted)
				wantWrites, wantDeletes := 0, 0
				switch change {
				case "add-last":
					addr := addressesFor(ipv6, 8)[7]
					mal.add(decision(addr))
					want = append(want, addr)
					wantWrites = 1
				case "remove-last":
					mal.remove(decision(sorted[6]))
					want = want[:6]
					wantDeletes = 1
				case "add-first":
					addr := "1.0.0.1"
					if ipv6 {
						addr = "2001:db8::0000"
					}
					mal.add(decision(addr))
					want = append(want, addr)
					wantWrites = 3
				case "remove-first":
					mal.remove(decision(sorted[0]))
					want = want[1:]
					wantWrites, wantDeletes = 2, 1
				case "remove-all":
					for _, addr := range sorted {
						mal.remove(decision(addr))
					}
					want = nil
					wantDeletes = 3
				}
				mal.updateFirewall(context.Background(), ipv6)
				assertBlocklist(t, f, want, ipv6, maxGroupSize)
				if len(f.writes) != wantWrites || len(f.deleted) != wantDeletes {
					t.Fatalf("writes/deletes = %d/%d, want %d/%d", len(f.writes), len(f.deleted), wantWrites, wantDeletes)
				}
				if len(mal.firewallGroupMembers[ipv6]) != len(f.groups) || len(f.rules) != len(f.groups) {
					t.Fatal("obsolete cache or rule survived group removal")
				}
				// One decision can move at most one member across each sorted boundary.
				if change == "add-first" {
					churn := 0
					for name, after := range memberships(f) {
						for _, addr := range before[name] {
							if !slices.Contains(after, addr) {
								churn++
							}
						}
						for _, addr := range after {
							if !slices.Contains(before[name], addr) {
								churn++
							}
						}
					}
					if churn > 2*len(f.groups) {
						t.Fatalf("excessive membership churn: %d", churn)
					}
				}
			})
		}
	}
}

func TestFailedWritesDoNotAdvanceCache(t *testing.T) {
	testSettings(t, 3)
	for _, create := range []bool{false, true} {
		t.Run(fmt.Sprintf("create=%t", create), func(t *testing.T) {
			f := newFakeUnifi()
			mal := loadTestState(f)
			name := "cs-unifi-bouncer-ipv4-0"
			id := ""
			if !create {
				id = mal.postFirewallGroup(context.Background(), "", name, false, []string{"10.0.0.1"})
			}
			beforeIDs := len(mal.firewallGroups[false])
			beforeMembers := slices.Clone(mal.firewallGroupMembers[false][name])
			f.writeErr = errors.New("controller unavailable")
			g := &unifi.FirewallGroup{ID: id, Name: name, GroupType: "address-group", GroupMembers: []string{"10.0.0.2"}}
			if _, err := mal.writeFirewallGroup(context.Background(), g, false); !errors.Is(err, f.writeErr) {
				t.Fatalf("write error = %v", err)
			}
			if beforeIDs != len(mal.firewallGroups[false]) || mal.firewallGroups[false][name] != id || !slices.Equal(beforeMembers, mal.firewallGroupMembers[false][name]) {
				t.Fatal("failed write advanced cache")
			}
			f.writeErr = nil
			if mal.postFirewallGroup(context.Background(), id, name, false, g.GroupMembers) == "" {
				t.Fatal("retry did not write desired membership")
			}
		})
	}
}

func TestSuccessfulEmptyResponseAndCacheOwnership(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)
	name := "cs-unifi-bouncer-ipv4-0"
	id := mal.postFirewallGroup(context.Background(), "", name, false, []string{"10.0.0.1"})
	f.writeErr = fmt.Errorf("empty response: %w", unifi.ErrNotFound)
	members := []string{"10.0.0.3", "10.0.0.2"}
	if got := mal.postFirewallGroup(context.Background(), id, name, false, members); got != id {
		t.Fatalf("empty successful response lost group ID: %s", got)
	}
	if members[0] != "10.0.0.3" {
		t.Fatal("sorting mutated caller's slice")
	}
	members[0] = "10.0.0.9"
	f.writes = nil
	mal.postFirewallGroup(context.Background(), id, name, false, []string{"10.0.0.2", "10.0.0.3"})
	if len(f.writes) != 0 {
		t.Fatal("acknowledged membership was not cached independently")
	}
}

func TestEmptyCreateResponseIsStillAnError(t *testing.T) {
	testSettings(t, 3)
	f := newFakeUnifi()
	mal := loadTestState(f)
	f.writeErr = fmt.Errorf("empty response: %w", unifi.ErrNotFound)
	g := &unifi.FirewallGroup{Name: "cs-unifi-bouncer-ipv4-0", GroupType: "address-group", GroupMembers: []string{"10.0.0.1"}}
	if _, err := mal.writeFirewallGroup(context.Background(), g, false); !errors.Is(err, unifi.ErrNotFound) {
		t.Fatalf("empty create response error = %v", err)
	}
	if len(mal.firewallGroups[false]) != 0 || len(mal.firewallGroupMembers[false]) != 0 {
		t.Fatal("failed create populated cache")
	}
}
