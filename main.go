package main

import (
	"context"
	"fmt"
	"time"

	"github.com/filipowm/go-unifi/unifi"
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

type FirewallGroupCache struct {
	id      string
	members map[string]bool
}

type unifiAddrList struct {
	c                      unifi.Client
	blockedAddresses       map[bool]map[string]bool
	addressToGroup         map[bool]map[string]int    // tracks which group each IP belongs to
	modifiedGroups         map[bool]map[int]bool      // tracks which groups need updating
	firewallGroups         map[bool]map[string]FirewallGroupCache
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

	// modified flag is set by decisionProcess when new/deleted decisions arrive
	// No need to force it true - the cache now persists existing state from UniFi

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
