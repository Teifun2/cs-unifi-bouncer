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

	// Validate is the go-swagger generated validation from the CrowdSec SDK and is
	// the same check the Local API runs; in particular it rejects metric items
	// without a "unit" (crowdsecurity/crowdsec#4409).
	if err := payload.Validate(strfmt.Default); err != nil {
		t.Fatalf("metrics payload should be accepted by LAPI validation: %v", err)
	}

	if len(payload.RemediationComponents) != 1 {
		t.Fatalf("expected 1 remediation component, got %d", len(payload.RemediationComponents))
	}
	rc := payload.RemediationComponents[0]
	if rc.Name != "cs-unifi-bouncer" {
		t.Fatalf("remediation component name = %q, want %q", rc.Name, "cs-unifi-bouncer")
	}
	if rc.Type != "daemon bouncer" {
		t.Fatalf("remediation component type = %q, want %q", rc.Type, "daemon bouncer")
	}
	if rc.Version == nil || *rc.Version != "test-version" {
		t.Fatalf("remediation component version = %v, want %q", rc.Version, "test-version")
	}
	if rc.UtcStartupTimestamp == nil || *rc.UtcStartupTimestamp != 900 {
		t.Fatalf("utc startup timestamp = %v, want 900", rc.UtcStartupTimestamp)
	}
	if len(rc.Metrics) != 1 {
		t.Fatalf("expected 1 metrics entry, got %d", len(rc.Metrics))
	}
	metrics := rc.Metrics[0]
	if metrics.Meta == nil {
		t.Fatal("metrics meta is nil")
	}
	if metrics.Meta.UtcNowTimestamp == nil || *metrics.Meta.UtcNowTimestamp != 1900 {
		t.Fatalf("utc now timestamp = %v, want 1900", metrics.Meta.UtcNowTimestamp)
	}
	if metrics.Meta.WindowSizeSeconds == nil || *metrics.Meta.WindowSizeSeconds != 900 {
		t.Fatalf("window size = %v, want 900", metrics.Meta.WindowSizeSeconds)
	}
	if len(metrics.Items) != 4 {
		t.Fatalf("expected 4 metric items, got %d", len(metrics.Items))
	}

	assertMetricItem(t, metrics.Items, "dropped", "ipv4", 12, "request", "ban")
	assertMetricItem(t, metrics.Items, "dropped", "ipv6", 3, "request", "ban")
	assertMetricItem(t, metrics.Items, "active_decisions", "ipv4", 2, "ip", "")
	assertMetricItem(t, metrics.Items, "active_decisions", "ipv6", 1, "ip", "")
}

func TestBuildMetricsPayloadWithNoCounts(t *testing.T) {
	mc := &metricsCollector{
		mal: &unifiAddrList{
			blockedAddresses: map[bool]map[string]bool{false: {}, true: {}},
		},
		lastPollTime: 1000,
		startupTime:  900,
		version:      "test-version",
		osName:       "linux",
		osVersion:    "test",
	}

	payload := mc.buildMetricsPayload(1900, metricCounts{})
	if err := payload.Validate(strfmt.Default); err != nil {
		t.Fatalf("empty metrics payload should be accepted by LAPI validation: %v", err)
	}
	if len(payload.RemediationComponents) != 1 || len(payload.RemediationComponents[0].Metrics) != 1 {
		t.Fatal("unexpected empty payload structure")
	}

	items := payload.RemediationComponents[0].Metrics[0].Items
	if len(items) != 4 {
		t.Fatalf("expected 4 metric items, got %d", len(items))
	}
	for _, item := range items {
		if item.Value == nil || *item.Value != 0 {
			t.Fatalf("metric %v has value %v, want 0", item.Name, item.Value)
		}
	}
}

func TestAddBlockedFlow(t *testing.T) {
	bouncerIPv4a := unifi.TrafficFlowPolicy{Name: "cs-unifi-bouncer-ipv4-External->Internal-0"}
	bouncerIPv4b := unifi.TrafficFlowPolicy{Name: "cs-unifi-bouncer-ipv4-External->Vpn-0"}
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
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{otherPolicy, bouncerIPv4a}},
			wantIPv4: 1,
		},
		{
			name:     "blocked by bouncer ipv6 policy",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{bouncerIPv6}},
			wantIPv6: 1,
		},
		{
			name: "allowed flow is not counted",
			flow: unifi.TrafficFlow{Action: "allowed", Policies: []unifi.TrafficFlowPolicy{bouncerIPv4a}},
		},
		{
			name: "blocked by another policy is not counted",
			flow: unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{otherPolicy}},
		},
		{
			name: "blocked flow with no policies is not counted",
			flow: unifi.TrafficFlow{Action: "blocked"},
		},
		{
			name:     "flow matching several bouncer policies is counted once",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{bouncerIPv4a, bouncerIPv4b}},
			wantIPv4: 1,
		},
		{
			name:     "flow matching bouncer and non-bouncer policies is counted once",
			flow:     unifi.TrafficFlow{Action: "blocked", Policies: []unifi.TrafficFlowPolicy{otherPolicy, bouncerIPv4a, bouncerIPv4b}},
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
		name     string
		policies []unifi.TrafficFlowPolicy
		want     string
		ok       bool
	}{
		{name: "ipv4", policies: []unifi.TrafficFlowPolicy{{Name: "cs-unifi-bouncer-ipv4-External->Internal-0"}}, want: "ipv4", ok: true},
		{name: "ipv6", policies: []unifi.TrafficFlowPolicy{{Name: "cs-unifi-bouncer-ipv6-External->Internal-0"}}, want: "ipv6", ok: true},
		{name: "legacy ipv4 rule", policies: []unifi.TrafficFlowPolicy{{Name: "cs-unifi-bouncer-ipv4-0"}}, want: "ipv4", ok: true},
		{name: "legacy ipv6 rule", policies: []unifi.TrafficFlowPolicy{{Name: "cs-unifi-bouncer-ipv6-0"}}, want: "ipv6", ok: true},
		{name: "unrelated policy", policies: []unifi.TrafficFlowPolicy{{Name: "Guest Network"}}, ok: false},
		{name: "empty policy name", policies: []unifi.TrafficFlowPolicy{{Name: ""}}, ok: false},
		{
			name: "unrelated policy before bouncer policy",
			policies: []unifi.TrafficFlowPolicy{
				{Name: "Guest Network"},
				{Name: "cs-unifi-bouncer-ipv4-0"},
			},
			want: "ipv4",
			ok:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := bouncerPolicyIPType(tt.policies)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("got (%q, %t), want (%q, %t)", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func assertMetricItem(t *testing.T, items []*models.MetricsDetailItem, name, ipType string, wantValue float64, wantUnit, wantRemediation string) {
	t.Helper()

	for _, item := range items {
		if item == nil || item.Name == nil || *item.Name != name || item.Labels["ip_type"] != ipType {
			continue
		}
		if item.Unit == nil || *item.Unit != wantUnit {
			t.Fatalf("metric %s/%s has unit %v, want %q", name, ipType, item.Unit, wantUnit)
		}
		if item.Value == nil || *item.Value != wantValue {
			t.Fatalf("metric %s/%s has value %v, want %v", name, ipType, item.Value, wantValue)
		}
		if item.Labels["origin"] == "" {
			t.Fatalf("metric %s/%s has no origin label", name, ipType)
		}
		if wantRemediation != "" && item.Labels["remediation"] != wantRemediation {
			t.Fatalf("metric %s/%s has remediation %q, want %q", name, ipType, item.Labels["remediation"], wantRemediation)
		}
		return
	}

	t.Fatalf("metric %s/%s not found", name, ipType)
}
