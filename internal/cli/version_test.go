// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
	"github.com/luckyPipewrench/pipelock/internal/release"
)

func TestVersionCmd(t *testing.T) {
	cmd := versionCmd()

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.Run(cmd, nil)

	output := buf.String()
	if !strings.Contains(output, "pipelock version") {
		t.Errorf("expected 'pipelock version' in output, got: %s", output)
	}
	if !strings.Contains(output, "build date:") {
		t.Errorf("expected 'build date:' in output, got: %s", output)
	}
	if !strings.Contains(output, "git commit:") {
		t.Errorf("expected 'git commit:' in output, got: %s", output)
	}
	if !strings.Contains(output, "go version:") {
		t.Errorf("expected 'go version:' in output, got: %s", output)
	}
}

func TestVersionCmd_ReleaseVerification(t *testing.T) {
	originalKeyring := release.PublicKeyringHex
	t.Cleanup(func() { release.PublicKeyringHex = originalKeyring })
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	key := hex.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	const (
		available = "available (embedded keyring)"
		missing   = "unavailable (no embedded keys)"
		invalid   = "unavailable (invalid embedded keyring)"
	)
	for _, tc := range []struct {
		name, keyring, want string
	}{
		{"missing", "", missing},
		{"whitespace", " \t\n", missing},
		{"valid", key, available},
		{"multiple", key + ", " + key, available},
		{"malformed", "not-hex", invalid},
		{"short", key[:len(key)-2], invalid},
		{"malformed after valid", key + ",not-hex", invalid},
		{"empty after valid", key + ",", invalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			release.PublicKeyringHex = tc.keyring
			cmd := versionCmd()
			var out strings.Builder
			cmd.SetOut(&out)
			cmd.Run(cmd, nil)
			want := fmt.Sprintf("pipelock version %s\n  build date: %s\n  git commit: %s\n  go version: %s\n  release verification: %s\n",
				cliutil.Version, cliutil.BuildDate, cliutil.GitCommit, cliutil.GoVersion, tc.want)
			if got := out.String(); got != want {
				t.Fatalf("version output = %q, want %q", got, want)
			}
		})
	}
}

func TestVersionCmd_ContainsVersion(t *testing.T) {
	cmd := versionCmd()

	buf := &strings.Builder{}
	cmd.SetOut(buf)
	cmd.Run(cmd, nil)

	output := buf.String()
	if !strings.Contains(output, cliutil.Version) {
		t.Errorf("expected output to contain version %q, got: %s", cliutil.Version, output)
	}
}
