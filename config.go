package main

import (
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/spf13/viper"
)

var (
	logLevel               string
	crowdsecBouncerAPIKey  string
	crowdsecBouncerURL     string
	crowdsecOrigins        []string
	crowdsecUpdateInterval string
	unifiHost              string
	unifiSite              string
	unifiAPIKey            string
	unifiUsername          string
	unifiPassword          string
	useIPV6                bool
	maxGroupSize           int
	ipv4StartRuleIndex     int
	ipv6StartRuleIndex     int
	skipTLSVerify          bool
	unifiLogging           bool
	unifiZoneSrc           []string
	unifiZoneDst           []string
	unifiPolicyReordering  bool
)

func initConfig() {
	viper.BindEnv("log_level")
	viper.SetDefault("log_level", "info")
	viper.BindEnv("crowdsec_bouncer_api_key")
	viper.BindEnv("crowdsec_url")
	viper.SetDefault("crowdsec_url", "http://crowdsec:8080/")
	viper.BindEnv("crowdsec_update_interval")
	viper.SetDefault("crowdsec_update_interval", "5s")
	viper.BindEnv("crowdsec_origins")
	viper.SetDefault("crowdsec_origins", nil)
	viper.BindEnv("unifi_host")
	viper.BindEnv("unifi_api_key")
	viper.BindEnv("unifi_user")
	viper.BindEnv("unifi_pass")
	viper.BindEnv("unifi_site")
	viper.SetDefault("unifi_site", "default")
	viper.BindEnv("unifi_ipv6")
	viper.SetDefault("unifi_ipv6", "true")
	viper.BindEnv("unifi_max_group_size")
	viper.SetDefault("unifi_max_group_size", 10000)
	viper.BindEnv("unifi_ipv4_start_rule_index")
	viper.SetDefault("unifi_ipv4_start_rule_index", 22000)
	viper.BindEnv("unifi_ipv6_start_rule_index")
	viper.SetDefault("unifi_ipv6_start_rule_index", 27000)
	viper.BindEnv("unifi_max_group_size")
	viper.SetDefault("unifi_max_group_size", 10000)
	viper.BindEnv("unifi_skip_tls_verify")
	viper.SetDefault("unifi_skip_tls_verify", "false")
	viper.BindEnv("unifi_logging")
	viper.SetDefault("unifi_logging", "false")
	viper.BindEnv("unifi_zone_src")
	viper.SetDefault("unifi_zone_src", "External")
	viper.BindEnv("unifi_zone_dst")
	viper.SetDefault("unifi_zone_dst", "Internal Vpn Hotspot")
	viper.BindEnv("unifi_policy_reordering")
	viper.SetDefault("unifi_policy_reordering", "false")

	logLevel = viper.GetString("log_level")
	level, err := zerolog.ParseLevel(logLevel)
	if err != nil {
		log.Fatal().Err(err).Msg("invalid log level")
	}
	zerolog.SetGlobalLevel(level)

	crowdsecBouncerAPIKey = viper.GetString("crowdsec_bouncer_api_key")
	if crowdsecBouncerAPIKey == "" {
		log.Fatal().Msg("Crowdsec API key is not set")
	}
	crowdsecBouncerURL = viper.GetString("crowdsec_url")
	if crowdsecBouncerURL == "" {
		log.Fatal().Msg("Crowdsec URL is not set")
	}

	crowdsecOrigins = viper.GetStringSlice("crowdsec_origins")

	crowdsecUpdateInterval = viper.GetString("crowdsec_update_interval")

	unifiHost = viper.GetString("unifi_host")

	unifiAPIKey = viper.GetString("unifi_api_key")
	unifiUsername = viper.GetString("unifi_user")
	unifiPassword = viper.GetString("unifi_pass")

	if unifiAPIKey == "" && (unifiUsername == "" || unifiPassword == "") {
		log.Fatal().Msg("Unifi API key or username/password is not set")
	}

	unifiSite = viper.GetString("unifi_site")

	useIPV6 = viper.GetBool("unifi_ipv6")

	maxGroupSize = viper.GetInt("unifi_max_group_size")

	ipv4StartRuleIndex = viper.GetInt("unifi_ipv4_start_rule_index")
	ipv6StartRuleIndex = viper.GetInt("unifi_ipv6_start_rule_index")

	skipTLSVerify = viper.GetBool("unifi_skip_tls_verify")

	unifiLogging = viper.GetBool("unifi_logging")

	unifiZoneSrc = viper.GetStringSlice("unifi_zone_src")
	unifiZoneDst = viper.GetStringSlice("unifi_zone_dst")

	unifiPolicyReordering = viper.GetBool("unifi_policy_reordering")
}
