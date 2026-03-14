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
}

type ZoneCache struct {
	id string
}

type unifiAddrList struct {
	c                     unifi.Client
	blockedAddresses      map[bool]map[string]bool
	firewallGroups        map[bool]map[string]string
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
		sshConfig = createSSHConfig(unifiLogCleanupUser, unifiLogCleanupPassword)
		if err := testSSHConnection(unifiHost); err != nil {
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
	if unifiLogCleanup {
		cleanupTimer = time.NewTicker(time.Duration(unifiLogCleanupMinutes) * time.Minute)
		defer cleanupTimer.Stop()
		cleanupChan = cleanupTimer.C
		log.Info().Msgf("Audit log cleanup will run every %d minutes", unifiLogCleanupMinutes)
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
					if err := cleanupBouncerAuditEntries(unifiHost, unifiLogCleanupMinutes); err != nil {
						log.Warn().Err(err).Msg("Scheduled audit log cleanup failed (non-fatal)")
					}
				}
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}
}
