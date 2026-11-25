// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package proxy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsTLSCRLSchannel drives the built-in Schannel curl through TLS
// interception with default revocation checking, which needs the leaf CRL
// distribution point to succeed.
func TestWindowsTLSCRLSchannel(t *testing.T) {
	proxyURL, cfg, _, target := startTLSCRLHTTPSProxy(t)
	// Select the built-in client even if Git's OpenSSL curl precedes it on PATH.
	curl := filepath.Join(os.Getenv("SystemRoot"), "System32", "curl.exe")
	version, err := exec.CommandContext(t.Context(), curl, "--version").CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
	if err != nil || !strings.Contains(strings.ToLower(string(version)), "schannel") {
		t.Fatalf("native Schannel curl unavailable: %v: %s", err, version)
	}
	output, err := exec.CommandContext(t.Context(), curl, "--silent", "--show-error", "--fail", "--max-time", "15", "--noproxy", "", "--proxy", proxyURL.String(), "--cacert", cfg.TLSInterception.CACertPath, target).CombinedOutput() // #nosec G204 G702 -- the Windows-only test runs the built-in curl under SystemRoot.
	if err != nil || string(output) != testTLSCRLBody {
		t.Fatalf("Schannel HTTPS request: %v: %s", err, output)
	}
}
