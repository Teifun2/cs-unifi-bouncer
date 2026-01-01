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
	c                      unifi.Client
	blockedAddresses       map[bool]map[string]bool
	firewallGroups         map[bool]map[string]string
	firewallRule           map[bool]map[string]FirewallRuleCache
	firewallZonePolicy     map[bool]map[string]FirewallZonePolicyCache
	modified               bool
	isZoneBased            bool
	firewallZones          map[string]ZoneCache
	initialReorderingDone  bool
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

	bouncer := &csbouncer.StreamBouncer{
		APIKey:         crowdsecBouncerAPIKey,
		APIUrl:         crowdsecBouncerURL,
		TickerInterval: crowdsecUpdateInterval,
		Origins:        crowdsecOrigins,
		UserAgent:      fmt.Sprintf("cs-unifi-bouncer/%s", version),
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

	// At startup, we need to call all update functions to ensure the firewall is in sync with the decisions
	mal.modified = true

	g.Go(func() error {
		log.Printf("Processing new and deleted decisions . . .")
		for {
			select {
			case <-ctx.Done():
				log.Error().Msg("terminating bouncer process")
				return nil
			case decisions := <-bouncer.Stream:
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
			}
		}
	})

	err := g.Wait()

	if err != nil {
		log.Error().Err(err).Send()
	}
}
