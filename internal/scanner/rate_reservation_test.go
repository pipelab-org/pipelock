// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func rateReservationScanner() *Scanner {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
	return MustNew(cfg)
}

func TestScanConnectReservationIsOneUseAndKeepsIdleDebit(t *testing.T) {
	const target = "https://api.vendor.example/page"
	s := rateReservationScanner()
	t.Cleanup(s.Close)

	connect, reservation := s.ScanConnect(t.Context(), target)
	if !connect.Allowed || reservation == nil {
		t.Fatalf("CONNECT scan = %+v, reservation=%v; want allowed scan and committed slot proof", connect, reservation)
	}

	first := s.ScanWithReservation(t.Context(), target, reservation)
	if !first.Allowed {
		t.Fatalf("first inner scan should claim CONNECT debit: %+v", first)
	}
	second := s.ScanWithReservation(t.Context(), target, reservation)
	if second.Allowed || second.Scanner != ScannerRateLimit {
		t.Fatalf("second inner scan reused reservation: %+v", second)
	}

	idle := rateReservationScanner()
	t.Cleanup(idle.Close)
	if result, proof := idle.ScanConnect(t.Context(), target); !result.Allowed || proof == nil {
		t.Fatalf("idle CONNECT scan = %+v, proof=%v", result, proof)
	}
	if result := idle.Scan(t.Context(), target); result.Allowed || result.Scanner != ScannerRateLimit {
		t.Fatalf("idle CONNECT debit was refunded: %+v", result)
	}
	if result, _ := idle.ScanConnect(t.Context(), target); result.Allowed || result.Scanner != ScannerRateLimit {
		t.Fatalf("later CONNECT did not pay for idle tunnel: %+v", result)
	}
}

func TestConnectReservationDoesNotChangeOtherScanEntryPoints(t *testing.T) {
	const target = "https://api.vendor.example/page"
	s := rateReservationScanner()
	t.Cleanup(s.Close)
	if result, proof := s.ScanConnect(t.Context(), target); !result.Allowed || proof == nil {
		t.Fatalf("CONNECT scan = %+v proof=%v", result, proof)
	}
	for _, tc := range []struct {
		name string
		scan func() Result
	}{
		{name: "ordinary scan", scan: func() Result { return s.Scan(t.Context(), target) }},
		{name: "preflight", scan: func() Result { return s.ScanPreflight(t.Context(), target) }},
		{name: "websocket", scan: func() Result { return s.ScanWebSocket(t.Context(), "wss://api.vendor.example/page") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scan(); got.Allowed || got.Scanner != ScannerRateLimit {
				t.Fatalf("entry point received CONNECT credit: %+v", got)
			}
		})
	}
}

func TestScanWithReservationRejectsInvalidProofs(t *testing.T) {
	const target = "https://api.vendor.example/page"
	t.Run("zero value", func(t *testing.T) {
		s := rateReservationScanner()
		t.Cleanup(s.Close)
		if got, _ := s.ScanConnect(t.Context(), target); !got.Allowed {
			t.Fatalf("CONNECT scan: %+v", got)
		}
		got := s.ScanWithReservation(t.Context(), target, &RateReservation{})
		if got.Allowed || got.Scanner != ScannerRateLimit {
			t.Fatalf("zero-value proof granted free capacity: %+v", got)
		}
	})

	t.Run("wrong host", func(t *testing.T) {
		s := rateReservationScanner()
		t.Cleanup(s.Close)
		_, proof := s.ScanConnect(t.Context(), target)
		s.rateLimiter.Record(baseDomain("api.other.example"))
		got := s.ScanWithReservation(t.Context(), "https://api.other.example/page", proof)
		if got.Allowed || got.Scanner != ScannerRateLimit {
			t.Fatalf("proof for another base domain granted capacity: %+v", got)
		}
	})

	t.Run("wrong limiter", func(t *testing.T) {
		connectScanner := rateReservationScanner()
		t.Cleanup(connectScanner.Close)
		otherScanner := rateReservationScanner()
		t.Cleanup(otherScanner.Close)
		_, proof := connectScanner.ScanConnect(t.Context(), target)
		if got, _ := otherScanner.ScanConnect(t.Context(), target); !got.Allowed {
			t.Fatalf("other scanner CONNECT scan: %+v", got)
		}
		got := otherScanner.ScanWithReservation(t.Context(), target, proof)
		if got.Allowed || got.Scanner != ScannerRateLimit {
			t.Fatalf("proof crossed limiter instances: %+v", got)
		}
	})

	t.Run("expired original slot", func(t *testing.T) {
		s := rateReservationScanner()
		t.Cleanup(s.Close)
		_, proof := s.ScanConnect(t.Context(), target)
		old := time.Now().Add(-time.Minute - time.Nanosecond)
		proof.timestamp = old
		s.rateLimiter.mu.Lock()
		s.rateLimiter.requests[baseDomain("api.vendor.example")] = []time.Time{old, time.Now()}
		s.rateLimiter.mu.Unlock()
		got := s.ScanWithReservation(t.Context(), target, proof)
		if got.Allowed || got.Scanner != ScannerRateLimit || proof.consumed.Load() {
			t.Fatalf("expired proof was accepted or consumed: %+v consumed=%t", got, proof.consumed.Load())
		}
	})

	t.Run("retired scanner generation", func(t *testing.T) {
		s := rateReservationScanner()
		_, proof := s.ScanConnect(t.Context(), target)
		s.Close()
		got := s.ScanWithReservation(t.Context(), target, proof)
		if got.Allowed || got.Scanner != ScannerRateLimit {
			t.Fatalf("retired generation accepted prepaid proof: %+v", got)
		}
	})

	t.Run("consumed", func(t *testing.T) {
		s := rateReservationScanner()
		t.Cleanup(s.Close)
		_, proof := s.ScanConnect(t.Context(), target)
		if got := s.ScanWithReservation(t.Context(), target, proof); !got.Allowed {
			t.Fatalf("first claim: %+v", got)
		}
		got := s.ScanWithReservation(t.Context(), target, proof)
		if got.Allowed || got.Scanner != ScannerRateLimit {
			t.Fatalf("consumed proof granted free capacity: %+v", got)
		}
	})
}

func TestRateReservationExpiresAtOriginalMinuteBoundary(t *testing.T) {
	const domain = "vendor.example"
	base := time.Unix(1_800_000_000, 0).UTC()

	t.Run("before boundary", func(t *testing.T) {
		rl := NewRateLimiter(2)
		rl.lastCleanup = base
		allowed, proof := rl.checkAndRecordAt(domain, nil, true, base)
		if !allowed || proof == nil {
			t.Fatalf("initial debit allowed=%t proof=%v", allowed, proof)
		}
		allowed, next := rl.checkAndRecordAt(domain, proof, false, base.Add(time.Minute-time.Nanosecond))
		if !allowed || next != nil || !proof.consumed.Load() || len(rl.requests[domain]) != 1 || !rl.requests[domain][0].Equal(base) {
			t.Fatalf("pre-boundary claim allowed=%t next=%v consumed=%t slots=%v", allowed, next, proof.consumed.Load(), rl.requests[domain])
		}
	})

	t.Run("at boundary", func(t *testing.T) {
		rl := NewRateLimiter(2)
		rl.lastCleanup = base
		_, proof := rl.checkAndRecordAt(domain, nil, true, base)
		boundary := base.Add(time.Minute)
		allowed, next := rl.checkAndRecordAt(domain, proof, false, boundary)
		if !allowed || next != nil || proof.consumed.Load() || len(rl.requests[domain]) != 1 || !rl.requests[domain][0].Equal(boundary) {
			t.Fatalf("boundary fallback allowed=%t next=%v consumed=%t slots=%v", allowed, next, proof.consumed.Load(), rl.requests[domain])
		}
	})
}

func TestScanConnectDoesNotMintOnEarlyFailureOrDisabledLimit(t *testing.T) {
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		target    string
		configure func(*config.Config)
		want      string
	}{
		{name: "cancelled context", ctx: cancelled, target: "https://api.vendor.example/page", want: ScannerContext},
		{name: "early path traversal", ctx: context.Background(), target: "https://api.vendor.example/a/../b", want: ScannerPathTraversal},
		{name: "disabled limiter", ctx: context.Background(), target: "https://api.vendor.example/page", configure: func(cfg *config.Config) { cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0 }, want: ScannerAll},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			cfg.DLP.ScanEnv = false
			cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
			if tc.configure != nil {
				tc.configure(cfg)
			}
			s := MustNew(cfg)
			t.Cleanup(s.Close)
			got, proof := s.ScanConnect(tc.ctx, tc.target)
			if got.Scanner != tc.want || proof != nil {
				t.Fatalf("ScanConnect = %+v proof=%v, want scanner=%s and no proof", got, proof, tc.want)
			}
		})
	}
}

func TestScanWithReservationKeepsEarlierURLChecks(t *testing.T) {
	const clean = "https://api.vendor.example/page"
	s := rateReservationScanner()
	t.Cleanup(s.Close)
	_, proof := s.ScanConnect(t.Context(), clean)

	credential := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		name, target, scanner string
	}{
		{name: "core DLP", target: "https://api.vendor.example/?token=" + credential, scanner: ScannerCoreDLP},
		{name: "metadata SSRF", target: "https://169.254.169.254/latest/meta-data/", scanner: ScannerCoreSSRF},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.ScanWithReservation(t.Context(), tc.target, proof)
			if got.Allowed || got.Scanner != tc.scanner || proof.consumed.Load() {
				t.Fatalf("reserved scan = %+v consumed=%t; want %s block before claiming proof", got, proof.consumed.Load(), tc.scanner)
			}
		})
	}

	if got := s.ScanWithReservation(t.Context(), clean, proof); !got.Allowed || !proof.consumed.Load() {
		t.Fatalf("earlier denials consumed the slot proof: %+v consumed=%t", got, proof.consumed.Load())
	}
}

func TestScanWithReservationContextCancellationDoesNotConsume(t *testing.T) {
	const target = "https://api.vendor.example/page"
	s := rateReservationScanner()
	t.Cleanup(s.Close)
	_, proof := s.ScanConnect(t.Context(), target)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if got := s.ScanWithReservation(ctx, target, proof); got.Allowed || got.Scanner != ScannerContext || proof.consumed.Load() {
		t.Fatalf("cancelled claim = %+v consumed=%t; want context block without claim", got, proof.consumed.Load())
	}
	if got := s.ScanWithReservation(t.Context(), target, proof); !got.Allowed || !proof.consumed.Load() {
		t.Fatalf("valid request after cancellation failed to claim slot: %+v consumed=%t", got, proof.consumed.Load())
	}
}

func TestScanConnectEntropyRescanDebitsOnlyOnce(t *testing.T) {
	const target = "https://www.vendor.example/media/Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl"
	cfg := queryEntropyParamExclusionTestConfig()
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 1
	s := MustNew(cfg)
	t.Cleanup(s.Close)

	first, proof := s.ScanConnect(t.Context(), target)
	if first.Allowed || first.Scanner != ScannerEntropy || proof != nil {
		t.Fatalf("first scan = %+v proof=%v, want early entropy block without debit proof", first, proof)
	}
	allowCtx := WithIssuerPathAllowance(t.Context(), func(path string) bool {
		return path == "/media/Zx9KqWvB3nMpLrT7yFhJ2dGsQ8aEcVbN4uXoIzPwRmKtYgD5fHl"
	})
	rescanned, proof := s.ScanConnect(allowCtx, target)
	if !rescanned.Allowed || proof == nil {
		t.Fatalf("relieved scan = %+v proof=%v, want one successful debit proof", rescanned, proof)
	}
	if got := s.Scan(allowCtx, target); got.Allowed || got.Scanner != ScannerRateLimit {
		t.Fatalf("entropy rescan did not debit exactly once: %+v", got)
	}
}
