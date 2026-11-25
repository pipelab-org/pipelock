// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner_test

import (
	"context"
	"math/rand/v2"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestPublicExamplesPreserveCredentialEnforcement(t *testing.T) {
	sampleID := "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
	samplePAN := strings.Repeat("4242", 4)
	const (
		upper             = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		mixed             = upper + "abcdefghijklmnopqrstuvwxyz"
		digits            = "0123456789"
		awsID             = "AWS Access ID"
		awsAssignmentRule = "AWS Secret Key"
		card              = "Credit Card Number"
	)

	randomString := func(rng *rand.Rand, alphabet string, size int) string {
		out := make([]byte, size)
		for i := range out {
			out[i] = alphabet[rng.IntN(len(alphabet))]
		}
		return string(out)
	}
	insert := func(rng *rand.Rand, value, example string) string {
		at := 1 + rng.IntN(len(value)-1)
		return value[:at] + example + value[at:]
	}
	awsAssignment := strings.Join([]string{"AWS", "SECRET", "ACCESS", "KEY"}, "_") + "="
	generatePAN := func(rng *rand.Rand) string {
		// Keep the generated issuer range disjoint from the published test PANs.
		return cardtest.Issuer("4019"+randomString(rng, digits, 11), 16)
	}
	cases := []struct {
		name, rule string
		generate   func(*rand.Rand) string
		embedded   func(*rand.Rand) string
	}{
		{"AWS access ID", awsID, func(rng *rand.Rand) string {
			return "AK" + "IA" + "Z" + randomString(rng, upper, 15)
		}, func(*rand.Rand) string {
			return "AK" + "IA" + samplePAN
		}},
		{"AWS secret assignment", awsAssignmentRule, func(rng *rand.Rand) string {
			return awsAssignment + randomString(rng, mixed, 40)
		}, func(rng *rand.Rand) string {
			body := randomString(rng, mixed, 18)
			return awsAssignment + insert(rng, body, "+"+sampleID+"/")
		}},
		{"Anthropic", "Anthropic API Key", func(rng *rand.Rand) string {
			return "sk-ant-api03-" + randomString(rng, mixed, 80)
		}, func(rng *rand.Rand) string {
			return "sk-ant-api03-" + insert(rng, randomString(rng, mixed, 58), "-"+sampleID+"-")
		}},
		{"GitHub", "GitHub Token", func(rng *rand.Rand) string {
			return "ghp_" + randomString(rng, mixed, 36)
		}, func(rng *rand.Rand) string {
			return "ghp_" + insert(rng, randomString(rng, mixed, 20), samplePAN)
		}},
		{"Slack", "Slack Token", func(rng *rand.Rand) string {
			return "xoxb-" + randomString(rng, digits, 24)
		}, func(rng *rand.Rand) string {
			return "xoxb-" + insert(rng, randomString(rng, digits, 24), "-"+samplePAN+"-")
		}},
		{"contiguous PAN", card, generatePAN, nil},
		{"grouped PAN", card, func(rng *rand.Rand) string {
			return cardtest.Grouped(generatePAN(rng), "-")
		}, nil},
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	queryURL := func(text string) string {
		return "https://api.vendor.example/?value=" + url.QueryEscape(text)
	}
	textScans := []struct {
		name string
		scan func(context.Context, string) scanner.TextDLPResult
	}{
		{"outbound text", sc.ScanTextForDLP},
		{"inbound text", sc.ScanTextForDLPInbound},
	}
	checkEnforcement := func(t *testing.T, seed uint64, placement, input, rule string) {
		t.Helper()
		for _, surface := range textScans {
			got := surface.scan(t.Context(), input)
			found := slices.ContainsFunc(got.Matches, func(m scanner.TextDLPMatch) bool {
				return m.PatternName == rule && !m.Warn && !m.IsInformational()
			})
			if got.Clean || !found {
				t.Errorf("seed %d %s %s: expected enforcing %s match, clean=%t, matches=%+v", seed, placement, surface.name, rule, got.Clean, got.Matches)
			}
		}
		// The URL CRLF guard runs before DLP. Use the HTML spelling of
		// newlines to reach DLP's decoded query view.
		got := sc.Scan(t.Context(), queryURL(strings.ReplaceAll(input, "\n", "&#10;")))
		spans := got.Spans()
		if got.Allowed || got.Scanner != scanner.ScannerDLP && got.Scanner != scanner.ScannerCoreDLP || len(spans) == 0 {
			t.Errorf("seed %d %s URL query: expected DLP enforcement for %s, got allowed=%t scanner=%q spans=%+v", seed, placement, rule, got.Allowed, got.Scanner, spans)
		}
		// URL Scan returns the first enforcing rule. Adjacent fields can
		// independently trigger an earlier rule in a joined URL view.
		if (placement == "standalone" || placement == "example inside") && !strings.Contains(input, sampleID) {
			if !slices.ContainsFunc(spans, func(span scanner.MatchSpan) bool { return span.RuleID == rule }) {
				t.Errorf("seed %d %s URL query: expected %s, got spans=%+v", seed, placement, rule, spans)
			}
		}
	}

	// The published sample ID placed
	// right after a short prefix, where rewriting it once blinded the real
	// credential around it. Random placement rarely reaches this position.
	t.Run("embedded near prefix", func(t *testing.T) {
		checkEnforcement(t, 0, "example inside", "sk-ant-api03-AAA-"+sampleID+"-"+strings.Repeat("B", 80), "Anthropic API Key")
		checkEnforcement(t, 0, "example inside", strings.ToLower(awsAssignment[:len(awsAssignment)-1])+" = abc+"+sampleID+"/def123456789012", awsAssignmentRule)
	})

	delimiters := []string{"-", "_", "+", "/", ".", " ", ",", "\"", "&", "\n"}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for seed := uint64(0); seed < 40; seed++ {
				rng := rand.New(rand.NewPCG(seed, 0x91e9)) // #nosec G404 -- deterministic property corpus.
				credential := tc.generate(rng)
				checkEnforcement(t, seed, "standalone", credential, tc.rule)
				delim := delimiters[seed%uint64(len(delimiters))]
				example := []string{sampleID, samplePAN}[(seed/uint64(len(delimiters)))%2]
				// Quote the credential when the separator would consume a
				// word or provider-token boundary.
				if delim == "_" || delim == "-" && tc.name == "Anthropic" {
					credential = "\"" + credential + "\""
				}

				checkEnforcement(t, seed, "example before", example+delim+credential, tc.rule)
				checkEnforcement(t, seed, "example after", credential+delim+example, tc.rule)
				checkEnforcement(t, seed, "between examples", sampleID+delim+credential+delim+samplePAN, tc.rule)
				if tc.embedded != nil {
					checkEnforcement(t, seed, "example inside", tc.embedded(rng), tc.rule)
				}
			}
		})
	}

	for _, tc := range []struct{ name, example, rule string }{
		{"bare Visa example", samplePAN, card},
		{"bare Amex example", "3782" + "822463" + "10005", card},
		{"bare Mastercard example", "5555" + "5555" + "5555" + "4444", card},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, surface := range textScans {
				got := surface.scan(t.Context(), tc.example)
				found := slices.ContainsFunc(got.InformationalMatches, func(m scanner.TextDLPMatch) bool {
					return m.PatternName == tc.rule && m.Warn && m.IsInformational()
				})
				if !got.Clean || len(got.Matches) != 0 || !found {
					t.Errorf("%s: expected only informational %s finding, got %+v", surface.name, tc.rule, got)
				}
			}
			got := sc.Scan(t.Context(), queryURL(tc.example))
			found := slices.ContainsFunc(got.WarnMatches, func(m scanner.WarnMatch) bool { return m.PatternName == tc.rule })
			if !got.Allowed || !found {
				t.Errorf("URL query: expected only informational %s finding, got %+v", tc.rule, got)
			}
		})
	}
}
