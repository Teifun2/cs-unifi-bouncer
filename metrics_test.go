package main

import (
	"testing"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/go-openapi/strfmt"
)

func TestBuildMetricsPayloadIsValid(t *testing.T) {
	mc := &metricsCollector{
		mal: &unifiAddrList{
			blockedAddresses: map[bool]map[string]bool{
				false: {"203.0.113.10": true, "198.51.100.20": true},
				true:  {"2001:db8::1": true},
			},
		},
		lastPollTime: 1000,
		startupTime:  900,
		version:      "test-version",
		osName:       "linux",
		osVersion:    "test",
	}

	payload := mc.buildMetricsPayload(1900, metricCounts{ipv4: 12, ipv6: 3})

	// Validate runs the same payload validation as the Local API; in particular
	// it rejects metric items without a "unit" (crowdsecurity/crowdsec#4409).
	if err := payload.Validate(strfmt.Default); err != nil {
		t.Fatalf("metrics payload should be accepted by LAPI validation: %v", err)
	}

	items := payload.RemediationComponents[0].Metrics[0].Items
	if len(items) != 4 {
		t.Fatalf("expected 4 metric items, got %d", len(items))
	}

	assertMetricItem(t, items, metricDropped, ipTypeIPv4, 12, metricUnitRequest)
	assertMetricItem(t, items, metricDropped, ipTypeIPv6, 3, metricUnitRequest)
	assertMetricItem(t, items, metricActiveDecisions, ipTypeIPv4, 2, metricUnitIP)
	assertMetricItem(t, items, metricActiveDecisions, ipTypeIPv6, 1, metricUnitIP)
}

func TestAddBlockedFlow(t *testing.T) {
	bouncerIPv4 := unifi.TrafficFlowPolicy{Name: "cs-unifi-bouncer-ipv4-External->Internal-0"}
	bouncerIPv6 := unifi.TrafficFlowPolicy{Name: "cs-unifi-bouncer-ipv6-External->Internal-0"}
	otherPolicy := unifi.TrafficFlowPolicy{Name: "Allow Established Sessions"}

	tests := []struct {
		name     string
		flow     unifi.TrafficFlow
		wantIPv4 int64
		wantIPv6 int64
	}{
		{
			name:     "blocked by bouncer ipv4 policy",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{otherPolicy, bouncerIPv4}},
			wantIPv4: 1,
		},
		{
			name:     "blocked by bouncer ipv6 policy",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{bouncerIPv6}},
			wantIPv6: 1,
		},
		{
			name: "allowed flow is not counted",
			flow: unifi.TrafficFlow{Action: "allowed", Policies: []unifi.TrafficFlowPolicy{bouncerIPv4}},
		},
		{
			name: "blocked by another policy is not counted",
			flow: unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{otherPolicy}},
		},
		{
			name:     "flow matching several bouncer policies is counted once",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{bouncerIPv4, bouncerIPv6}},
			wantIPv4: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var counts metricCounts
			counts.addBlockedFlow(tt.flow)
			if counts.ipv4 != tt.wantIPv4 || counts.ipv6 != tt.wantIPv6 {
				t.Fatalf("got ipv4=%d ipv6=%d, want ipv4=%d ipv6=%d", counts.ipv4, counts.ipv6, tt.wantIPv4, tt.wantIPv6)
			}
		})
	}
}

func TestBouncerPolicyIPType(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   string
		ok     bool
	}{
		{name: "ipv4", policy: "cs-unifi-bouncer-ipv4-External->Internal-0", want: ipTypeIPv4, ok: true},
		{name: "ipv6", policy: "cs-unifi-bouncer-ipv6-External->Internal-0", want: ipTypeIPv6, ok: true},
		{name: "legacy rule", policy: "cs-unifi-bouncer-ipv4-0", want: ipTypeIPv4, ok: true},
		{name: "unrelated policy", policy: "Guest Network", ok: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := bouncerPolicyIPType([]unifi.TrafficFlowPolicy{{Name: tt.policy}})
			if ok != tt.ok || got != tt.want {
				t.Fatalf("got (%q, %t), want (%q, %t)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func assertMetricItem(t *testing.T, items []*models.MetricsDetailItem, name, ipType string, wantValue float64, wantUnit string) {
	t.Helper()

	for _, item := range items {
		if item.Name == nil || *item.Name != name || item.Labels["ip_type"] != ipType {
			continue
		}
		if item.Unit == nil || *item.Unit != wantUnit {
			t.Fatalf("metric %s/%s has unit %v, want %q", name, ipType, item.Unit, wantUnit)
		}
		if item.Value == nil || *item.Value != wantValue {
			t.Fatalf("metric %s/%s has value %v, want %v", name, ipType, item.Value, wantValue)
		}
		return
	}

	t.Fatalf("metric %s/%s not found", name, ipType)
}
