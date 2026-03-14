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

func createSSHConfig(sshUser, sshPassword string) *ssh.ClientConfig {
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
	}
}

func testSSHConnection(unifiHost string) error {
	host, err := extractHost(unifiHost)
	if err != nil {
		return fmt.Errorf("failed to extract host from URL: %w", err)
	}

	client, err := ssh.Dial("tcp", host+":22", sshConfig)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection to %s: %w", host, err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	return nil
}

func cleanupBouncerAuditEntries(unifiHost string, lookbackMinutes int) error {
	host, err := extractHost(unifiHost)
	if err != nil {
		return fmt.Errorf("failed to extract host from URL: %w", err)
	}

	lookbackTime := time.Now().Add(-time.Duration(lookbackMinutes) * time.Minute).UnixMilli()

	mongoCmd := fmt.Sprintf(
		`mongo ace --port 27117 --quiet --eval 'db.admin_activity_log.updateMany({ "meta.display_property_value": { $regex: "^cs-unifi-bouncer-" }, time: { $gt: %d } }, { $set: { updates: [ { property_path: "description", new_value: "Updated from bouncer" } ] } })'`,
		lookbackTime,
	)

	log.Debug().Msgf("Executing cleanup command on host %s", host)

	client, err := ssh.Dial("tcp", host+":22", sshConfig)
	if err != nil {
		return fmt.Errorf("failed to establish SSH connection to %s: %w", host, err)
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
