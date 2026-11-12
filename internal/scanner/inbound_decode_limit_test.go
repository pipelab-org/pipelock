// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"slices"
	"strconv"
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

// Inbound content at a decode limit carries the partial-inspection warning
// without an inspection refusal.
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

// Independent JSON and quoted-printable chains form a decode graph that
// reaches the candidate cap before the byte cap (under 1 MiB of views).
func decodeCandidateLimitText() string {
	return `\` + strings.Repeat("u005c", 60) + "u0021!=" + strings.Repeat("3D", 60) + "21!"
}

func TestInboundDecodeWorkLimitsWarn(t *testing.T) {
	sc := decodeLimitScanner(t)
	for _, tc := range []struct {
		name            string
		text            string
		outboundRefuses bool
	}{
		{"candidate cap", decodeCandidateLimitText(), true},
		{"decoded byte cap", decodeBudgetNestedText(), true},
		// Outbound inspects a large terminal input; inbound retains its
		// existing whole-input decode shortcut, but must disclose the skip.
		{"oversized input", strings.Repeat("!", maxDecodeTotalBytes+1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, complete := decodeEncodingsBudgetMode(tc.text, true, 0, true)
			if tc.name == "candidate cap" {
				bytes := 0
				for _, view := range views {
					bytes += len(view.text)
				}
				if len(views) != maxDecodeCandidates || bytes >= maxDecodeTotalBytes {
					t.Fatalf("candidate fixture did not isolate the cap: views=%d bytes=%d", len(views), bytes)
				}
			}
			if complete {
				t.Error("inbound decoder reported a budget stop as complete")
			}
			ctx, release := WithSharedDecodes(t.Context())
			defer release()
			for _, shared := range []bool{false, true, true} {
				scanCtx := t.Context()
				if shared {
					scanCtx = ctx
				}
				r := sc.ScanTextForDLPInbound(scanCtx, tc.text)
				if !hasPartial(r) || !r.Clean || r.Incomplete || !OnlyInformational(r.Matches) {
					t.Errorf("inbound budget stop: shared=%v clean=%v incomplete=%v matches=%v", shared, r.Clean, r.Incomplete, matchNamesOf(r.Matches))
				}
			}
			r := sc.ScanTextForDLP(t.Context(), tc.text)
			if HasInspectionLimit(r.Matches) != tc.outboundRefuses || r.Clean == tc.outboundRefuses || hasPartial(r) {
				t.Errorf("outbound accounting changed: clean=%v matches=%v", r.Clean, matchNamesOf(r.Matches))
			}
		})
	}
}

func TestInboundDecodeWalkBudgetStops(t *testing.T) {
	roots := make([]decodedResult, maxDecodeCandidates)
	for i := range roots {
		roots[i] = decodedResult{text: "!" + strconv.Itoa(i), encoding: encodingHTML}
	}
	for _, tc := range []struct {
		name      string
		roots     []decodedResult
		minPrefix int
		wantViews int
	}{
		{"candidate roots", roots, 0, maxDecodeCandidates},
		{"byte root", []decodedResult{{text: strings.Repeat("!", maxDecodeTotalBytes)}}, 0, 1},
		{"prefix recovery byte root", []decodedResult{{text: strings.Repeat("!", maxDecodeTotalBytes+1)}}, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			views, complete := decodeEncodingsInboundWalkTracked(nil, nil, tc.roots, newDecodeSeen(), true, tc.minPrefix, true, nil)
			if complete || len(views) != tc.wantViews {
				t.Fatalf("budget stop: views=%d complete=%v", len(views), complete)
			}
		})
	}
}

func TestInboundDecodeLimitKeepsCardClassification(t *testing.T) {
	sc := decodeLimitScanner(t)
	// The strings reconstruct an enforcing card run; the independent deep
	// escape chain must keep its own warning outside that classification.
	text := `["4111","111111111111","` + percentChain(maxDecodeRounds+1) + `"]`
	r := sc.ScanTextForDLPInbound(t.Context(), text)
	card := false
	partial := 0
	for _, match := range r.Matches {
		if match.genericCard && !match.IsInformational() {
			card = true
		}
		if match.PatternName == PartialEncodedContentPattern {
			partial++
			if !match.IsInformational() || !match.Warn {
				t.Fatal("partial evidence reclassified as enforcing", match)
			}
		}
	}
	if !card || partial != 1 || r.Clean || HasInspectionLimit(r.Matches) {
		t.Fatalf("card or warning classification changed: clean=%v matches=%v", r.Clean, matchNamesOf(r.Matches))
	}
}
