package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/filipowm/go-unifi/unifi"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
)

type FirewallRuleCache struct {
	id      string
	groupId string
}

type FirewallZonePolicyCache struct {
	id      string
	groupId string
	index   int
	zoneSrc string
	zoneDst string
}

type ZoneCache struct {
	id string
}

// FirewallGroupCache tracks one UniFi firewall group managed by the bouncer.
// Membership is a set so placement/removal is O(1); touched records whether the
// membership changed since it was last acknowledged by the controller, so an
// unchanged group is never written again.
type FirewallGroupCache struct {
	id      string
	members map[string]bool
	touched bool
}

type unifiAddrList struct {
	c                     unifi.Client
	memberGroup           map[bool]map[string]string
	firewallGroups        map[bool]map[string]*FirewallGroupCache
	firewallRule          map[bool]map[string]FirewallRuleCache
	firewallZonePolicy    map[bool]map[string]FirewallZonePolicyCache
	modified              bool
	isZoneBased           bool
	firewallZones         map[string]ZoneCache
	initialReorderingDone bool
}

// This variable is set by the build process with ldflags
var version = "unknown"

func main() {
	// Configure zerolog to write to stderr with no buffering
	// This ensures logs appear immediately in container environments
	log.Logger = zerolog.New(os.Stderr).With().Timestamp().Logger()

	log.Info().Msg("Starting cs-unifi-bouncer with version: " + version)

	// zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	initConfig()

	// Initialize SSH config for audit log cleanup if enabled
	if unifiLogCleanup {
		log.Info().Msg("Audit log cleanup is enabled, testing SSH connection...")
		var err error
		sshConfig, err = createSSHConfig(unifiHost, unifiLogCleanupUser, unifiLogCleanupPassword)
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create SSH configuration")
		}
		if err := testSSHConnection(); err != nil {
			log.Fatal().Err(err).Msg("SSH connection test failed. Please check your SSH credentials and ensure SSH is enabled on your UniFi device.")
		}
		log.Info().Msg("SSH connection test successful")
	}

	bouncer := &csbouncer.StreamBouncer{
		APIKey:             crowdsecBouncerAPIKey,
		APIUrl:             crowdsecBouncerURL,
		TickerInterval:     crowdsecUpdateInterval,
		Origins:            crowdsecOrigins,
		UserAgent:          fmt.Sprintf("cs-unifi-bouncer/%s", version),
		InsecureSkipVerify: &crowdsecSkipTLSVerify,
	}
	if err := bouncer.Init(); err != nil {
		log.Fatal().Err(err).Msg("Bouncer init failed")
	}

	var mal unifiAddrList

	g, ctx := errgroup.WithContext(context.Background())

	mal.initUnifi(ctx)
	log.Info().Msg("Unifi Connection Initialized")

	g.Go(func() error {
		bouncer.Run(ctx)
		return fmt.Errorf("bouncer stream halted")
	})

	// Timer to detect inactivity initialization can take longer
	inactivityTimer := time.NewTimer(10 * time.Second)
	defer inactivityTimer.Stop()

	// Timer for periodic audit log cleanup
	var cleanupTimer *time.Ticker
	var cleanupChan <-chan time.Time
	var lastCleanupSuccess time.Time
	if unifiLogCleanup {
		cleanupTimer = time.NewTicker(time.Duration(unifiLogCleanupMinutes) * time.Minute)
		defer cleanupTimer.Stop()
		cleanupChan = cleanupTimer.C
		log.Info().Msgf("Audit log cleanup will run every %d minutes", unifiLogCleanupMinutes)

		// Initial cleanup without a lower time bound to remove old leftover entries
		log.Info().Msg("Running initial audit log cleanup for all entries...")
		startedAt := time.Now()
		if err := cleanupBouncerAuditEntries(unifiLogCleanupMinutes, lastCleanupSuccess); err != nil {
			log.Warn().Err(err).Msg("Initial audit log cleanup failed (non-fatal)")
		} else {
			lastCleanupSuccess = startedAt
		}
	}

	// Timer for metrics collection
	var metricsTimer *time.Ticker
	var metricsChan <-chan time.Time
	var collector *metricsCollector
	if enableMetrics {
		collector = newMetricsCollector(&mal, version)
		metricsTimer = time.NewTicker(time.Duration(crowdsecMetricsMinutes) * time.Minute)
		defer metricsTimer.Stop()
		metricsChan = metricsTimer.C
		log.Info().Msgf("CrowdSec metrics and UniFi traffic polling will run every %d minutes", crowdsecMetricsMinutes)
	}

	// At startup, we need to call all update functions to ensure the firewall is in sync with the decisions
	mal.modified = true

	g.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				log.Error().Msg("terminating bouncer process")
				return nil
			case decisions, ok := <-bouncer.Stream:
				if !ok {
					// Stream was closed, likely due to CrowdSec API authentication failure
					log.Error().Msg("CrowdSec API connection failed (check API key and URL)")
					return nil
				}
				// Reset the inactivity timer
				inactivityTimer.Reset(time.Second)

				mal.decisionProcess(decisions)
			case <-inactivityTimer.C:
				// Execute the update to unifi when no new messages have been received
				mal.updateFirewall(ctx, false)
				if useIPV6 {
					mal.updateFirewall(ctx, true)
				}
				mal.modified = false
			case <-cleanupChan:
				// Periodically clean up audit log entries
				if unifiLogCleanup {
					log.Debug().Msg("Running scheduled audit log cleanup...")
					startedAt := time.Now()
					if err := cleanupBouncerAuditEntries(unifiLogCleanupMinutes, lastCleanupSuccess); err != nil {
						log.Warn().Err(err).Msg("Scheduled audit log cleanup failed (non-fatal)")
					} else {
						lastCleanupSuccess = startedAt
					}
				}
			case <-metricsChan:
				if enableMetrics && collector != nil {
					collector.pollAndSendMetrics(ctx, bouncer.APIClient)
				}
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}
}
