package main

import (
	"bytes"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/ssh"
)

var sshConfig *ssh.ClientConfig
var sshHost string

func createSSHConfig(unifiHost, sshUser, sshPassword string) (*ssh.ClientConfig, error) {
	host, err := extractHost(unifiHost)
	if err != nil {
		return nil, fmt.Errorf("failed to extract host from URL: %w", err)
	}
	sshHost = host

	return &ssh.ClientConfig{
		User: sshUser,
		Auth: []ssh.AuthMethod{
			ssh.Password(sshPassword),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = sshPassword
				}
				return answers, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}, nil
}

func testSSHConnection() error {

	client, err := ssh.Dial("tcp", sshHost+":22", sshConfig)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection to %s: %w", sshHost, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	return nil
}

// cleanupWindow returns the [from, to] time range (unix millis) to clean up.
// The window always reaches back at least twice the cleanup interval so that
// consecutive runs overlap (cleanup is idempotent), and further back to the
// last successful run (minus one interval) if earlier runs failed. Without a
// previous successful run (e.g. at startup) there is no lower bound (from=0),
// so old leftover entries are cleaned as well.
func cleanupWindow(now, lastSuccess time.Time, lookbackMinutes int) (int64, int64) {
	if lastSuccess.IsZero() {
		return 0, now.UnixMilli()
	}
	interval := time.Duration(lookbackMinutes) * time.Minute
	from := now.Add(-2 * interval)
	if lastSuccess.Add(-interval).Before(from) {
		from = lastSuccess.Add(-interval)
	}
	return from.UnixMilli(), now.UnixMilli()
}

func cleanupBouncerAuditEntries(lookbackMinutes int, lastSuccess time.Time) error {
	from, to := cleanupWindow(time.Now(), lastSuccess, lookbackMinutes)

	mongoCmd := fmt.Sprintf(
		`mongo ace --port 27117 --quiet --eval 'db.admin_activity_log.updateMany({ "meta.display_property_value": { $regex: "^cs-unifi-bouncer-" }, time: { $gte: %d, $lte: %d } }, { $set: { updates: [ { property_path: "description", new_value: "Updated from bouncer" } ] } })'`,
		from, to,
	)

	log.Debug().Msgf("Executing cleanup command on host %s", sshHost)

	client, err := ssh.Dial("tcp", sshHost+":22", sshConfig)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection to %s: %w", sshHost, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	if err := session.Run(mongoCmd); err != nil {
		log.Warn().
			Str("stdout", stdout.String()).
			Str("stderr", stderr.String()).
			Msg("Mongo cleanup command output")
		return fmt.Errorf("mongo cleanup failed: %w", err)
	}

	output := strings.TrimSpace(stdout.String())
	if output != "" {
		log.Info().Msgf("Audit log cleanup completed: %s", output)
	} else {
		log.Debug().Msg("Audit log cleanup completed (no output)")
	}

	return nil
}

func extractHost(rawURL string) (string, error) {
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}

	host := u.Host
	if colonIdx := strings.LastIndex(host, ":"); colonIdx != -1 {
		if !strings.Contains(host, "]") || strings.LastIndex(host, "]") < colonIdx {
			host = host[:colonIdx]
		}
	}

	return host, nil
}
