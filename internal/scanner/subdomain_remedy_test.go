// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
)

// Each subdomain refusal's operator hint must name only a control its blocking
// path consults. The results come from the real scanner, and each named remedy
// is applied to prove it changes the outcome, while the threshold the old hint
// suggested is shown not to.
func TestSubdomainRefusalHintsNameControlsThatWork(t *testing.T) {
	const thresholdKnob = "subdomain_entropy_threshold"
	scan := func(t *testing.T, url string, exclusions []string, threshold float64) Result {
		t.Helper()
		cfg := testConfig()
		cfg.DLP.Patterns = nil // isolate the subdomain signals from DLP matches
		cfg.FetchProxy.Monitoring.SubdomainEntropyExclusions = exclusions
		if threshold > 0 {
			cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = threshold
		}
		s := MustNew(cfg)
		defer s.Close()
		return s.Scan(context.Background(), url)
	}

	for _, tc := range []struct {
		name, url, host, reasonPrefix string
	}{
		{"encoded label", "https://7365637265745f6170695f6b65795f3132333435.cdn.vendor.example/ping", "7365637265745f6170695f6b65795f3132333435.cdn.vendor.example", subdomainEncodedLabelReasonPrefix},
		{"chunked labels", "https://a1b2c3d4.e5f6a7b8.c9d0e1f2.a3b4c5d6.cdn.vendor.example/ping", "a1b2c3d4.e5f6a7b8.c9d0e1f2.a3b4c5d6.cdn.vendor.example", subdomainEncodedChunksReasonPrefix},
	} {
		t.Run(tc.name, func(t *testing.T) {
			blocked := scan(t, tc.url, nil, 0)
			if blocked.Allowed || blocked.Scanner != ScannerSubdomainEntropy || !strings.HasPrefix(blocked.Reason, tc.reasonPrefix) {
				t.Fatalf("baseline = %+v, want %q refusal", blocked, tc.reasonPrefix)
			}
			g, ok := GuidanceForResult(blocked.Scanner, blocked.Reason)
			if !ok || !strings.Contains(g.OperatorKnob, "subdomain_entropy_exclusions") || g.OperatorBroader != "" ||
				!strings.Contains(g.OperatorKnob, "does not lift it") {
				t.Fatalf("guidance = %+v, want the exclusion named and the threshold ruled out", g)
			}
			if r := scan(t, tc.url, []string{tc.host}, 0); !r.Allowed {
				t.Fatalf("named exclusion did not lift the refusal: %+v", r)
			}
			if r := scan(t, tc.url, nil, 7.9); r.Allowed || !strings.HasPrefix(r.Reason, tc.reasonPrefix) {
				t.Fatalf("threshold 7.9 result = %+v; the hint's claim that the threshold does not lift it is wrong", r)
			}
		})
	}

	// URL parsing refuses a malformed host before the subdomain check, so
	// drive the check directly, as the fail-closed lookup tests do.
	t.Run("malformed host", func(t *testing.T) {
		const host = "cdn0123456789ef..vendor.example"
		check := func(threshold float64) Result {
			cfg := testConfig()
			cfg.DLP.Patterns = nil
			if threshold > 0 {
				cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = threshold
			}
			s := MustNew(cfg)
			defer s.Close()
			return s.checkSubdomainEntropy(host)
		}
		blocked := check(0)
		if blocked.Allowed || blocked.Scanner != ScannerSubdomainEntropy || blocked.Reason != publicSuffixLookupFailedReason {
			t.Fatalf("baseline = %+v, want public suffix refusal", blocked)
		}
		g, ok := GuidanceForResult(blocked.Scanner, blocked.Reason)
		if !ok || !strings.Contains(g.OperatorKnob, "Correct the hostname") || g.OperatorBroader != "" ||
			strings.Contains(g.OperatorKnob, "exclusions") {
			t.Fatalf("guidance = %+v, want a hostname correction and no threshold remedy", g)
		}
		if r := check(7.9); r.Allowed {
			t.Fatalf("threshold lifted the malformed-host refusal: %+v", r)
		}
	})

	t.Run("label entropy keeps threshold guidance", func(t *testing.T) {
		g, ok := GuidanceForResult(ScannerSubdomainEntropy, `high entropy subdomain label "x" (4.10 > 4.00 threshold)`)
		if !ok || !strings.Contains(g.OperatorBroader, thresholdKnob) {
			t.Fatalf("label-entropy guidance = %+v, want the threshold option kept", g)
		}
	})
}
