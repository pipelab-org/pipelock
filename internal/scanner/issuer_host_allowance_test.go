// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// A host allowance relieves the heuristic subdomain-label finding for the one
// host it names and nothing else: structural exfiltration labels, DLP, SSRF and
// every other host keep their findings.
func TestScan_IssuerHostAllowanceRelievesOnlyHeuristicSubdomainEntropy(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	s := MustNew(cfg)
	defer s.Close()

	const entropic = "ab3xk9mz2wq7rl5yn8vc4jf6.vendor.example"
	structural := strings.Repeat("a1b2c3d4", 6) + ".vendor.example"
	secret := "AK" + "IA" + "Q9W8E7R6T5Y4U3I2"
	var asked []string
	allowing := func(host string) context.Context {
		return WithIssuerHostAllowance(context.Background(), func(candidate string) bool {
			asked = append(asked, candidate)
			return candidate == host
		})
	}
	for _, tt := range []struct {
		name      string
		ctx       context.Context
		url       string
		wantAllow bool
	}{
		{"no allowance", context.Background(), "https://" + entropic + "/a", false},
		{"allowance for the host", allowing(entropic), "https://" + entropic + "/a", true},
		{"allowance for another host", allowing("other.vendor.example"), "https://" + entropic + "/a", false},
		{"allowance never relieves a structural label", allowing(structural), "https://" + structural + "/a", false},
		{"allowance does not relieve DLP", allowing(entropic), "https://" + entropic + "/a?k=" + secret, false},
		{"allowance does not relieve path entropy", allowing(entropic), "https://" + entropic + "/Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl", false},
		{"allowance does not relieve SSRF", allowing("169.254.169.254"), "https://169.254.169.254/a", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := s.Scan(tt.ctx, tt.url)
			if got.Allowed != tt.wantAllow {
				t.Fatalf("Allowed = %v (%s %s), want %v", got.Allowed, got.Scanner, got.Reason, tt.wantAllow)
			}
		})
	}
	if len(asked) == 0 {
		t.Fatal("the allowance was never consulted")
	}
	// Premise: the entropic fixture is blocked by the heuristic, the other by a
	// structural finding, so the two cases above test the distinction.
	if res := s.Scan(context.Background(), "https://"+entropic+"/a"); res.Scanner != ScannerSubdomainEntropy || !res.IsEntropyOnly() {
		t.Fatalf("premise: entropic host = %+v", res)
	}
	if res := s.Scan(context.Background(), "https://"+structural+"/a"); res.Scanner != ScannerSubdomainEntropy || res.IsEntropyOnly() {
		t.Fatalf("premise: structural host = %+v", res)
	}
}
