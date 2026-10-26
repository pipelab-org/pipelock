// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/securefile"
)

// KillSwitchCredentialPrefix refers to systemd.exec(5)'s per-invocation,
// read-only credential directory. No other environment expansion is performed.
const KillSwitchCredentialPrefix = "$CREDENTIALS_DIRECTORY/"

// KillSwitchCredentialName returns the credential ID for a native systemd file
// reference, or an empty name for an ordinary file. systemd.exec(5) requires a
// short ASCII filename; this interface admits the portable filename subset.
func KillSwitchCredentialName(path string) (string, error) {
	if !strings.HasPrefix(path, "$CREDENTIALS_DIRECTORY") {
		return "", nil
	}
	// Linux limits.h NAME_MAX bounds credential filenames to 255 bytes.
	name, ok := strings.CutPrefix(path, KillSwitchCredentialPrefix)
	if !ok || name == "" || name == "." || name == ".." || len(name) > 255 {
		return "", errors.New("invalid kill_switch.api_token_file credential reference")
	}
	for _, c := range name {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' {
			continue
		}
		return "", errors.New("invalid kill_switch.api_token_file credential name")
	}
	return name, nil
}

func (c *Config) resolveKillSwitchTokenFile(configDir string) error {
	path := c.KillSwitch.APITokenFile
	if path == "" {
		return nil
	}
	if c.KillSwitch.APIToken != "" {
		return errors.New("kill_switch.api_token and api_token_file are mutually exclusive")
	}
	name, err := KillSwitchCredentialName(path)
	if err != nil {
		return err
	}
	if name != "" {
		dir := os.Getenv("CREDENTIALS_DIRECTORY")
		if !filepath.IsAbs(dir) {
			return errors.New("kill_switch.api_token_file requires an absolute CREDENTIALS_DIRECTORY")
		}
		path = filepath.Join(dir, name)
	} else if !filepath.IsAbs(path) {
		path = filepath.Join(configDir, path)
	}
	// Never include the file's path or contents in diagnostics: both may have
	// been derived from a credential-bearing configuration environment.
	data, err := securefile.Read(path, securefile.Options{MaxBytes: maxKillSwitchTokenFileBytes, DisallowedPerms: 0o027})
	if err != nil {
		return errors.New("cannot read kill_switch.api_token_file as a stable regular file")
	}
	// Text files commonly have a final newline. Preserve all other bytes;
	// bearer credentials cannot contain line breaks or NUL (RFC 6750 section 2.1).
	token := strings.TrimSuffix(strings.TrimSuffix(string(data), "\r\n"), "\n")
	if token == "" || strings.ContainsAny(token, "\r\n\x00") {
		return errors.New("kill_switch.api_token_file must contain a nonempty single-line bearer token")
	}
	for i := range len(token) {
		if token[i] < 0x21 || token[i] > 0x7e {
			return errors.New("kill_switch.api_token_file must contain visible ASCII without spaces")
		}
	}
	if override := os.Getenv(EnvKillSwitchAPIToken); override != "" {
		token = override
	}
	c.resolvedKillSwitchAPIToken = token
	c.killSwitchAPITokenWasResolved = true
	return nil
}

// systemd.exec(5) bounds a unit's complete credential set to 1 MiB. Apply the
// same ceiling to ordinary token files, including files outside systemd.
const maxKillSwitchTokenFileBytes = 1 << 20
