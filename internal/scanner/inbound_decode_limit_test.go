// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// decodeLimitKey builds the fake credential the chains below hide.
func decodeLimitKey() string { return "AK" + "IA" + strings.Repeat("V", 16) }

// percentChain hides the credential under n rounds of percent encoding.
func percentChain(n int) string {
	key := decodeLimitKey()
	return "token " + percentEncodeN(key[:1], n) + key[1:] + " end"
}

// entityChain hides the credential's first byte under n entity layers.
func entityChain(n int, withKey bool) string {
	key := decodeLimitKey()
	if !withKey {
		return "token &" + strings.Repeat("amp;", n) + "#65; end"
	}
	return "token &" + strings.Repeat("amp;", n) + "#65;" + key[1:] + " end"
}

func decodeLimitScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func matchNamesOf(matches []TextDLPMatch) []string {
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.PatternName)
	}
	return names
}

func hasPartial(r TextDLPResult) bool {
	return slices.Contains(matchNamesOf(r.Matches), PartialEncodedContentPattern) ||
		slices.Contains(matchNamesOf(r.InformationalMatches), PartialEncodedContentPattern)
}

// Josh's decision (2026-11-11): inbound content at a decode limit always
// carries the partial-inspection warning and is never refused.
func TestInboundDecodeLimitWarns(t *testing.T) {
	t.Parallel()
	sc := decodeLimitScanner(t)
	cases := []struct {
		name string
		text string
	}{
		{"percent chain one past the round limit", percentChain(maxDecodeRounds + 1)},
		{"percent chain far past the round limit", percentChain(2 * maxDecodeRounds)},
		{"entity chain one past the pass limit, no key", entityChain(maxHTMLEntityDecodePasses+1, false)},
		{"entity chain far past the pass limit, no key", entityChain(100, false)},
	}
	entries := map[string]func(context.Context, string) TextDLPResult{
		"ScanTextForDLPInbound": sc.ScanTextForDLPInbound,
		"ScanTextForDLPInbound with inbound direction": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInbound(WithInboundDirection(ctx), text)
		},
		"ScanTextForDLP under inbound direction": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLP(WithInboundDirection(ctx), text)
		},
		"ScanTextForDLPInboundWithCardView": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInboundWithCardView(ctx, text, text)
		},
		"ScanTextForDLPInboundWithTypedCardView": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInboundWithTypedCardView(ctx, text, text)
		},
		"ScanTextForDLPInboundStructuralView": func(ctx context.Context, text string) TextDLPResult {
			return sc.ScanTextForDLPInboundStructuralView(ctx, text, text)
		},
	}
	for _, tc := range cases {
		for entry, scan := range entries {
			t.Run(tc.name+"/"+entry, func(t *testing.T) {
				t.Parallel()
				r := scan(t.Context(), tc.text)
				if !hasPartial(r) {
					t.Fatalf("inbound scan stopped at a decode limit with no warning: clean=%v matches=%v", r.Clean, matchNamesOf(r.Matches))
				}
				if !r.Clean || r.Incomplete || HasEnforcingMatch(r.Matches) || HasInspectionLimit(r.Matches) {
					t.Fatalf("inbound limit warning must not refuse: clean=%v incomplete=%v matches=%v", r.Clean, r.Incomplete, matchNamesOf(r.Matches))
				}
				if !OnlyInformational(r.Matches) {
					t.Fatalf("limit warning is not informational: %v", matchNamesOf(r.Matches))
				}
			})
		}
	}
}

// The warning is evidence beside a real finding, never a replacement for it.
func TestInboundDecodeLimitKeepsRealFinding(t *testing.T) {
	t.Parallel()
	sc := decodeLimitScanner(t)
	for _, n := range []int{maxHTMLEntityDecodePasses + 1, 100} {
		r := sc.ScanTextForDLPInbound(t.Context(), entityChain(n, true))
		if r.Clean || !slices.Contains(matchNamesOf(r.Matches), "AWS Access ID") {
			t.Fatalf("entity chain n=%d lost the credential finding: %v", n, matchNamesOf(r.Matches))
		}
		if HasInspectionLimit(r.Matches) {
			t.Fatalf("entity chain n=%d refused inbound: %v", n, matchNamesOf(r.Matches))
		}
	}
}

// Outbound keeps refusing at a decode limit and gains no inbound warning.
func TestOutboundDecodeLimitStillRefuses(t *testing.T) {
	t.Parallel()
	sc := decodeLimitScanner(t)
	for name, text := range map[string]string{
		"percent": percentChain(maxDecodeRounds + 1),
		"entity":  entityChain(maxHTMLEntityDecodePasses+1, false),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := sc.ScanTextForDLP(t.Context(), text)
			if r.Clean || !HasInspectionLimit(r.Matches) {
				t.Fatalf("outbound limit hit was not refused: clean=%v matches=%v", r.Clean, matchNamesOf(r.Matches))
			}
			if hasPartial(r) {
				t.Fatalf("outbound refusal also carries the inbound warning: %v", matchNamesOf(r.Matches))
			}
		})
	}
}

// Text inside every limit produces no new warning, and a chain that fits is
// still decoded to its credential.
func TestInboundWithinDecodeLimitsNoWarning(t *testing.T) {
	t.Parallel()
	sc := decodeLimitScanner(t)
	for _, n := range []int{1, 5, maxHTMLEntityDecodePasses - 1} {
		if r := sc.ScanTextForDLPInbound(t.Context(), entityChain(n, false)); hasPartial(r) || len(r.Matches) != 0 || !r.Clean {
			t.Fatalf("entity chain n=%d warns inside the limit: %v", n, matchNamesOf(r.Matches))
		}
	}
	for _, text := range []string{"plain prose, nothing encoded", "a &amp; b &lt;tag&gt; 100%25 sure"} {
		if r := sc.ScanTextForDLPInbound(t.Context(), text); hasPartial(r) || len(r.Matches) != 0 || !r.Clean {
			t.Fatalf("ordinary text warns: %q %v", text, matchNamesOf(r.Matches))
		}
	}
	for _, n := range []int{1, 20, maxDecodeRounds - 1} {
		r := sc.ScanTextForDLPInbound(t.Context(), percentChain(n))
		if hasPartial(r) || !slices.Contains(matchNamesOf(r.Matches), "AWS Access ID") {
			t.Fatalf("percent chain n=%d: want the credential and no warning, got %v", n, matchNamesOf(r.Matches))
		}
	}
}
