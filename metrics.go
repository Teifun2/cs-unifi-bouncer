package main

import (
	"context"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csversion "github.com/crowdsecurity/go-cs-lib/version"
	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog/log"
)

const (
	metricDropped         = "dropped"
	metricActiveDecisions = "active_decisions"

	metricUnitRequest = "request"
	metricUnitIP      = "ip"

	ipTypeIPv4 = "ipv4"
	ipTypeIPv6 = "ipv6"
)

type metricsCollector struct {
	mal               *unifiAddrList
	lastPollTimeMilli int64
	lastPollTime      int64
	startupTime       int64
	version           string
	osName            string
	osVersion         string
}

// metricCounts holds the number of blocked flows or active decisions per IP family.
type metricCounts struct {
	ipv4 int64
	ipv6 int64
}

func newMetricsCollector(mal *unifiAddrList, version string) *metricsCollector {
	osName, osVersion := csversion.DetectOS()
	now := time.Now()
	return &metricsCollector{
		mal:               mal,
		lastPollTimeMilli: now.UnixMilli(),
		lastPollTime:      now.Unix(),
		startupTime:       now.Unix(),
		version:           version,
		osName:            osName,
		osVersion:         osVersion,
	}
}

func (mc *metricsCollector) pollAndSendMetrics(ctx context.Context, api *apiclient.ApiClient) {
	nowTime := time.Now()
	nowMilli := nowTime.UnixMilli()
	now := nowTime.Unix()

	dropped, err := mc.countDroppedFlows(ctx, nowMilli)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to fetch traffic flows for metrics from UniFi")
		return
	}
	log.Info().Msgf("Found %d blocked IPv4 and %d blocked IPv6 traffic flows in UniFi, reporting to CrowdSec", dropped.ipv4, dropped.ipv6)

	payload := mc.buildMetricsPayload(now, dropped)

	_, _, err = api.UsageMetrics.Add(ctx, payload)
	if err != nil {
		log.Warn().Err(err).Msg("failed to send metrics")
		return
	}

	mc.lastPollTimeMilli = nowMilli
	mc.lastPollTime = now
	log.Debug().Msg("usage metrics successfully sent")
}

// countDroppedFlows pages through the UniFi traffic flows recorded since the last
// successful metrics submission and counts the ones blocked by a bouncer policy.
func (mc *metricsCollector) countDroppedFlows(ctx context.Context, toMilli int64) (metricCounts, error) {
	req := &unifi.TrafficFlowsRequest{
		Action:        []string{"blocked"},
		TimestampFrom: mc.lastPollTimeMilli,
		TimestampTo:   toMilli,
		PageSize:      1000,
		PageNumber:    0,
	}

	var counts metricCounts

	for {
		flows, err := mc.mal.c.GetTrafficFlows(ctx, unifiSite, req)
		if err != nil {
			return metricCounts{}, err
		}

		for _, flow := range flows.Data {
			counts.addBlockedFlow(flow)
		}

		if !flows.HasNext || len(flows.Data) == 0 {
			break
		}

		req.PageNumber++
	}

	return counts, nil
}

// addBlockedFlow counts a flow if it was blocked by a policy created by this bouncer.
// A flow is counted once even when several bouncer policies matched it.
func (c *metricCounts) addBlockedFlow(flow unifi.TrafficFlow) {
	if flow.Action != "blocked" {
		return
	}

	ipType, matched := bouncerPolicyIPType(flow.Policies)
	if !matched {
		return
	}

	if ipType == ipTypeIPv6 {
		c.ipv6++
	} else {
		c.ipv4++
	}
}

// bouncerPolicyIPType returns the IP family of the first bouncer policy in the list.
// Bouncer policies and rules are named "cs-unifi-bouncer-<ipv4|ipv6>-...".
func bouncerPolicyIPType(policies []unifi.TrafficFlowPolicy) (string, bool) {
	for _, policy := range policies {
		if !strings.Contains(policy.Name, "cs-unifi-bouncer") {
			continue
		}
		if strings.HasPrefix(policy.Name, "cs-unifi-bouncer-ipv6") {
			return ipTypeIPv6, true
		}
		return ipTypeIPv4, true
	}

	return "", false
}

// buildMetricsPayload builds the remediation component metrics expected by the Local API.
// See https://docs.crowdsec.net/docs/next/contributing/specs/bouncer_metrics_specs
func (mc *metricsCollector) buildMetricsPayload(now int64, dropped metricCounts) *models.AllMetrics {
	window := now - mc.lastPollTime
	if window < 0 {
		window = 0
	}

	active := metricCounts{
		ipv4: int64(len(mc.mal.blockedAddresses[false])),
		ipv6: int64(len(mc.mal.blockedAddresses[true])),
	}

	// The bouncer does not retain the LAPI origin of each decision, so every
	// metric is reported under the generic "crowdsec" origin. Per-origin
	// breakdowns are therefore approximate (documented in README.md).
	items := []*models.MetricsDetailItem{
		newMetricItem(metricDropped, metricUnitRequest, float64(dropped.ipv4), models.MetricsLabels{
			"origin":      "crowdsec",
			"remediation": "ban",
			"ip_type":     ipTypeIPv4,
		}),
		newMetricItem(metricDropped, metricUnitRequest, float64(dropped.ipv6), models.MetricsLabels{
			"origin":      "crowdsec",
			"remediation": "ban",
			"ip_type":     ipTypeIPv6,
		}),
		// active_decisions is a gauge and must use the "ip" unit (see crowdsecurity/crowdsec#4409).
		newMetricItem(metricActiveDecisions, metricUnitIP, float64(active.ipv4), models.MetricsLabels{
			"origin":  "crowdsec",
			"ip_type": ipTypeIPv4,
		}),
		newMetricItem(metricActiveDecisions, metricUnitIP, float64(active.ipv6), models.MetricsLabels{
			"origin":  "crowdsec",
			"ip_type": ipTypeIPv6,
		}),
	}

	// "processed" is deliberately not reported: the bouncer only creates drop
	// policies, so it cannot observe units that bypassed a decision.
	return &models.AllMetrics{
		RemediationComponents: []*models.RemediationComponentsMetrics{
			{
				Name: "cs-unifi-bouncer",
				Type: "daemon bouncer",
				BaseMetrics: models.BaseMetrics{
					Version:             &mc.version,
					UtcStartupTimestamp: &mc.startupTime,
					FeatureFlags:        []string{},
					Os: &models.OSversion{
						Name:    &mc.osName,
						Version: &mc.osVersion,
					},
					Metrics: []*models.DetailedMetrics{
						{
							Items: items,
							Meta: &models.MetricsMeta{
								UtcNowTimestamp:   &now,
								WindowSizeSeconds: &window,
							},
						},
					},
				},
			},
		},
	}
}

func newMetricItem(name, unit string, value float64, labels models.MetricsLabels) *models.MetricsDetailItem {
	return &models.MetricsDetailItem{
		Name:   &name,
		Unit:   &unit,
		Value:  &value,
		Labels: labels,
	}
}
