// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"reflect"
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
			views, complete := decodeEncodingsInboundWalkTracked(nil, nil, tc.roots, newDecodeSeen(), inboundDecodeWalkOptions{includeURL: true, minPrefix: tc.minPrefix, withHTML: true, reportWorkLimits: true})
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

func TestInboundDecodeLimitSameNamedFinding(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: PartialEncodedContentPattern, Regex: `REVIEW_SENTINEL`, Severity: config.SeverityHigh,
	})
	sc := MustNew(cfg)
	defer sc.Close()
	warnings := 0
	sc.SetDLPWarnHook(func(_ context.Context, name, _ string) {
		if name == PartialEncodedContentPattern {
			warnings++
		}
	})
	r := sc.ScanTextForDLPInbound(t.Context(), "REVIEW_SENTINEL "+entityChain(maxHTMLEntityDecodePasses+1, false))
	finding, partial := false, 0
	for _, match := range r.Matches {
		if match.PatternName != PartialEncodedContentPattern {
			continue
		}
		if match.IsInformational() && match.Warn {
			partial++
		} else {
			finding = true
		}
	}
	if r.Clean || r.Incomplete || !finding || partial != 1 || warnings != 1 {
		t.Fatalf("same-named finding hid partial evidence: clean=%v finding=%v partial=%d warnings=%d matches=%v", r.Clean, finding, partial, warnings, matchNamesOf(r.Matches))
	}
}

func TestInboundDecodeTaggedCandidateLimitWarns(t *testing.T) {
	// This fixed prefix fills the tag walk at a segment root after duplicate
	// views are removed. Later segments would independently report exhaustion
	// and hide a queue skipped at entry.
	var body strings.Builder
	body.WriteString(strings.Repeat("z", 16))
	for i := range 3615 {
		body.WriteByte(';')
		body.WriteString("z0z0z0")
		body.WriteString(strconv.Itoa(1000 + i))
	}
	text := unicodeTags(body.String())
	for _, inbound := range []bool{false, true} {
		views, complete := decodeEncodingsBudgetMode(text, true, 0, inbound)
		t.Logf("inbound=%v views=%d complete=%v", inbound, len(views), complete)
		if len(views) != maxDecodeCandidates+1 {
			t.Fatalf("fixture did not reach the tag budget: views=%d", len(views))
		}
		// Outbound checks the last root and finds only an already-seen child;
		// inbound stops before that check and must disclose the skipped work.
		if complete == inbound {
			t.Errorf("tag segment completeness changed: inbound=%v complete=%v", inbound, complete)
		}
	}
	sc := decodeLimitScanner(t)
	r := sc.ScanTextForDLPInbound(t.Context(), text)
	if !r.Clean || !hasPartial(r) || !OnlyInformational(r.Matches) {
		t.Fatalf("tag candidate cap lost warning: clean=%v matches=%v", r.Clean, matchNamesOf(r.Matches))
	}
	if r := sc.ScanTextForDLP(t.Context(), text); !r.Clean || HasInspectionLimit(r.Matches) || hasPartial(r) {
		t.Fatal("tag candidate cap changed the complete outbound scan", matchNamesOf(r.Matches))
	}
}

// Keyword-gated scans and separate card views can use inbound accounting
// inside an outbound scan. Work warnings must follow the enclosing direction
// on repeated scans.
func TestOutboundCardDecodeWorkPolicy(t *testing.T) {
	for _, keywords := range []bool{false, true} {
		t.Run(strconv.FormatBool(keywords), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			if keywords {
				cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Context record", Regex: `RECORD_[A-Z]{8}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}})
			}
			sc := MustNew(cfg)
			defer sc.Close()
			text := strings.Repeat("!", maxDecodeTotalBytes+1)
			ctx, release := WithSharedDecodes(t.Context())
			defer release()
			for _, inbound := range []bool{true, false, true, false} {
				var r TextDLPResult
				if keywords {
					if inbound {
						r = sc.ScanTextForDLPInbound(ctx, text)
					} else {
						r = sc.ScanTextForDLP(ctx, text)
					}
				} else if inbound {
					r = sc.ScanTextForDLPInboundWithCardView(ctx, "ordinary", text)
				} else {
					r = sc.ScanTextForDLPWithCardView(ctx, "ordinary", text)
				}
				if !r.Clean || r.Incomplete || HasInspectionLimit(r.Matches) || hasPartial(r) != inbound {
					t.Fatalf("card work accounting changed: inbound=%v clean=%v matches=%v", inbound, r.Clean, matchNamesOf(r.Matches))
				}
			}
			// Existing depth refusals remain enforced in the outbound card pass.
			r := sc.ScanTextForDLPWithCardView(ctx, "ordinary", entityChain(maxHTMLEntityDecodePasses+1, false))
			if !HasInspectionLimit(r.Matches) {
				t.Fatal("outbound card pass lost its depth refusal", matchNamesOf(r.Matches))
			}
		})
	}
}

func TestSharedDecodeWorkReportingModes(t *testing.T) {
	ctx, release := WithSharedDecodes(t.Context())
	defer release()
	shared := sharedDecodesFrom(ctx)
	text := decodeCandidateLimitText()
	want := referenceDecodeEncodingsFixpoint(text, true)
	for _, report := range []bool{true, false, true, false} {
		key := decodingMemoKey{text: text, includeURL: true, inbound: true, reportWorkLimits: report}
		views, complete, retained := shared.decode(key)
		if !retained || complete == report || !reflect.DeepEqual(views, want) {
			t.Fatalf("cached work mode changed: report=%v complete=%v retained=%v views=%d", report, complete, retained, len(views))
		}
	}
	shared.mu.Lock()
	entries := len(shared.store.views)
	shared.mu.Unlock()
	if entries != 2 {
		t.Fatalf("reporting modes shared a cache entry: entries=%d", entries)
	}
}
