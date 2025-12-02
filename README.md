<p align="center">
<img src="https://github.com/teifun2/cs-unifi-bouncer/raw/main/docs/assets/crowdsec_unifi_logo.png" alt="CrowdSec" title="CrowdSec" width="300" height="280" />
</p>

# CrowdSec Unifi Bouncer

A CrowdSec Bouncer for Unifi appliance

![GitHub](https://img.shields.io/github/license/teifun2/cs-unifi-bouncer)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/teifun2/cs-unifi-bouncer)
[![Go Report Card](https://goreportcard.com/badge/github.com/teifun2/cs-unifi-bouncer)](https://goreportcard.com/report/github.com/teifun2/cs-unifi-bouncer)
[![Maintainability](https://qlty.sh/badges/c1f1c4cf-fabf-45bb-a5c2-4ad04ec6d4ac/maintainability.svg)](https://qlty.sh/gh/Teifun2/projects/cs-unifi-bouncer)
[![ci](https://github.com/teifun2/cs-unifi-bouncer/actions/workflows/container-release.yaml/badge.svg)](https://github.com/teifun2/cs-unifi-bouncer/actions/workflows/container-release.yaml)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/teifun2/cs-unifi-bouncer)

> [!WARNING]
> This was tested with the following [devices](#tested-devices). Further testing is needed

# Description

This repository aim to implement a [CrowdSec](https://doc.crowdsec.net/) bouncer for the routers of [Unifi](https://www.ui.com/) to block malicious IP to access your services.
For this it leverages [Unifi API](https://ubntwiki.com/products/software/unifi-controller/api) to populate a dynamic Firewall Address List. Specically the Go Library [go-unifi](https://github.com/filipowm/go-unifi) is used.

# Acknowledgment

This is a Fork of [funkolab/cs-mikrotik-bouncer](https://github.com/funkolab/cs-mikrotik-bouncer) and would not have been possible without this previous work

# Tested Devices

- [x] Dream Machine Pro (UDM-Pro)
- [x] Dream Machine SE (UDM-SE)
- [ ] Dream Machine Pro Max (UDM-Pro-Max)
- [x] Gateway Lite (UXG-Lite)
- [ ] Gateway Pro (UXG-Pro)
- [ ] Gateway Enterprise (UXG-Enterprise)
- [ ] Cloud Gateway Max (UCG-Max)
- [x] Cloud Gateway Ultra (UCG-Ultra)
- [x] Cloud Gateway Fiber (UCG-Fiber)
- [x] UniFi Express (UX)
- [ ] Dream Wall (DW)
- [ ] Enterprise Fortress Gateway (EFG)

# Usage

For now, this web service is mainly thought to be used as a container.  
If you need to build from source, you can get some inspiration from the Dockerfile.

## Prerequisites

You should have a Unifi appliance and a CrowdSec instance running.  
The container is available as docker image `ghcr.io/teifun2/cs-unifi-bouncer`. It must have access to CrowdSec and to Unifi.

Generate a bouncer API key following [CrowdSec documentation](https://doc.crowdsec.net/docs/cscli/cscli_bouncers_add)

## Procedure

1. Get a bouncer API key from your CrowdSec with command `cscli bouncers add unifi-bouncer`
2. Copy the API key printed. You **_WON'T_** be able the get it again.
3. Paste this API key as the value for bouncer environment variable `CROWDSEC_BOUNCER_API_KEY`, instead of "MyApiKey"
4. Start bouncer with `docker-compose up bouncer` in the `example` directory
5. It will directly communicate with your Unifi appliance and configure Rules and IP Groups

## Configuration

The bouncer configuration is made via environment variables:

| Name                          | Description                                                                                                                               | Default                 | Required |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------- | :------: |
| `CROWDSEC_BOUNCER_API_KEY`    | CrowdSec bouncer API key required to be authorized to request local API                                                                   | `none`                  |    ✅    |
| `CROWDSEC_URL`                | Host and port of CrowdSec agent                                                                                                           | `http://crowdsec:8080/` |    ✅    |
| `CROWDSEC_ORIGINS`            | Space separated list of CrowdSec origins to filter from LAPI (EG: "crowdsec cscli")                                                       | `none`                  |    ❌    |
| `CROWDSEC_UPDATE_INTERVAL`    | Interval Frequency Querying the Crowdsec API for changes to the blocklist.                                                                | `5s`                    |    ❌    |
| `LOG_LEVEL`                   | Minimum log level for bouncer in [zerolog levels](https://pkg.go.dev/github.com/rs/zerolog#readme-leveled-logging)                        | `1`                     |    ❌    |
| `UNIFI_HOST`                  | Unifi appliance address                                                                                                                   | `none`                  |    ✅    |
| `UNIFI_API_KEY`               | Unifi appliance API key                                                                                                                   | `none`                  | ✅ / ❌  |
| `UNIFI_USER`                  | Unifi appliance username                                                                                                                  | `none`                  | ✅ / ❌  |
| `UNIFI_PASS`                  | Unifi appliance password                                                                                                                  | `none`                  | ✅ / ❌  |
| `UNIFI_IPV6`                  | Enable / Disable IPv6 support                                                                                                             | `true`                  |    ❌    |
| `UNIFI_SITE`                  | Unifi Site Configuration in case of multiple sites                                                                                        | `default`               |    ❌    |
| `UNIFI_MAX_GROUP_SIZE`        | UDM has a max IP Group size of 10'000 This might be different for other appliances                                                        | `10000`                 |    ❌    |
| `UNIFI_IPV4_START_RULE_INDEX` | If you have other custom Rules defined in your Firewall this might need to be changed to prevent collisions (NOT FOR ZONE BASED FIREWALL) | `22000`                 |    ❌    |
| `UNIFI_IPV6_START_RULE_INDEX` | If you have other custom Rules defined in your Firewall this might need to be changed to prevent collisions (NOT FOR ZONE BASED FIREWALL) | `27000`                 |    ❌    |
| `UNIFI_SKIP_TLS_VERIFY`       | Skips Certificate check for unifi controllers without proper SSL Certificate                                                              | `false`                 |    ❌    |
| `UNIFI_LOGGING`               | Generate Syslog entries when the firewall rules are matched                                                                               | `false`                 |    ❌    |
| `UNIFI_ZONE_SRC`              | Space separated list of Source Zones for Firewall Policy in Zone Based mode                                                               | `External`              |    ❌    |
| `UNIFI_ZONE_DST`              | Space separated list of Destination Zones for Firewall Policy in Zone Based mode                                                          | `Internal Vpn Hotspot`  |    ❌    |
| `UNIFI_POLICY_REORDERING`     | Enable automatic reordering of firewall policies to ensure cs-unifi-bouncer policies are positioned after default policies                | `true`                  |    ❌    |
| `UNIFI_LOG_CLEANUP`           | Enable automatic cleanup of MongoDB audit log entries to prevent CPU overload (see [Troubleshooting](#mongodb-cpu-overload))              | `false`                 |    ❌    |
| `UNIFI_LOG_CLEANUP_USER`      | SSH username for audit log cleanup (usually `root` for UDM devices)                                                                       | `root`                  |    ❌    |
| `UNIFI_LOG_CLEANUP_PASSWORD`  | SSH password for audit log cleanup                                                                                                        | `none`                  | ✅ if cleanup enabled |
| `UNIFI_LOG_CLEANUP_MINUTES`   | How far back (in minutes) to clean up audit log entries                                                                                   | `30`                    |    ❌    |

# Troubleshooting

## MongoDB CPU Overload

Some users have reported that the UniFi control plane becomes slow or unresponsive after running the bouncer for a while. This is caused by the UniFi controller logging every individual IP address change to the `admin_activity_log` collection in MongoDB, which can grow very large (1GB+) and cause high CPU usage (300%+).

**Symptoms:**
- UniFi console becomes slow or unresponsive
- Console shows "Getting ready" for extended periods
- `mongod` process at 300%+ CPU usage
- Network continues to work, but control plane is unusable

**Solution:**

Enable the audit log cleanup feature by setting these environment variables:

```yaml
environment:
  UNIFI_LOG_CLEANUP: "true"
  UNIFI_LOG_CLEANUP_USER: "root"
  UNIFI_LOG_CLEANUP_PASSWORD: "your-ssh-password"
```

This feature connects via SSH to your UniFi device after each firewall update and cleans up the verbose audit log entries, replacing thousands of individual IP entries with a simple "Updated from bouncer" message. This preserves the audit trail while eliminating the performance impact.

**Note:** You need to enable SSH access on your UniFi device and know the root password. The SSH password is typically the same as your device's management password.

# Contribution

Any constructive feedback is welcome, feel free to add an issue or a pull request. I will review it and integrate it to the code.
