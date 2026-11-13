// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// One character glued to a boundary-anchored credential must be a finding.
// PR #1391's hyphenated prose (desk, kiosk, risk, task, and a repeated letter
// suffix) must stay clean. A digit glued to a card or SSN stays clean: it
// lengthens the number instead of disguising it.
func TestGluedBoundaryCredential(t *testing.T) {
	s := gluedBoundaryScanner(t)
	for _, tc := range gluedBoundaryCases() {
		t.Run(tc.name, func(t *testing.T) {
			text := "note: " + tc.prefix + tc.secret + " end"
			got := s.ScanTextForDLP(context.Background(), text)
			if tc.want {
				if !gluedBoundaryFound(got.Matches, got.InformationalMatches, tc.pattern) {
					t.Fatalf("text DLP clean=%v matches=%v informational=%v, want %s", got.Clean, gluedMatchNames(got.Matches), gluedMatchNames(got.InformationalMatches), tc.pattern)
				}
			} else if gluedBoundaryFound(got.Matches, got.InformationalMatches, tc.pattern) {
				t.Fatalf("text DLP flagged %s in %q", tc.pattern, text)
			}

			target := "https://api.vendor.example/v1/items?ref=" + url.QueryEscape(tc.prefix+tc.secret)
			urlResult := s.Scan(context.Background(), target)
			blocked := gluedBoundaryURLBlock(urlResult, tc.pattern)
			if tc.want && !blocked {
				t.Fatalf("URL allowed=%v scanner=%q reason=%q, want DLP %s", urlResult.Allowed, urlResult.Scanner, urlResult.Reason, tc.pattern)
			}
			if !tc.want && blocked {
				t.Fatalf("URL flagged %s: %s", tc.pattern, urlResult.Reason)
			}
		})
	}
}

// A zero-width character makes the normalized view differ from the source.
// The finding has to survive that path, which suppresses source boundary misses.
func TestGluedBoundaryCredentialNormalizedView(t *testing.T) {
	s := gluedBoundaryScanner(t)
	secret := gluedAnthropicKey()
	text := "note\u200b: x" + secret
	got := s.ScanTextForDLP(context.Background(), text)
	if !gluedBoundaryFound(got.Matches, got.InformationalMatches, "Anthropic API Key") {
		t.Fatalf("normalized view missed glued anthropic key: clean=%v matches=%v", got.Clean, gluedMatchNames(got.Matches))
	}
}

func TestGluedBoundaryProseStaysClean(t *testing.T) {
	s := gluedBoundaryScanner(t)
	prose := []string{
		"the desk-ant-hill-clearance-report-final",
		"desk-ant-" + strings.Repeat("a", 20),
		"kiosk-proj-" + strings.Repeat("a", 20),
		"kiosk-admin-" + strings.Repeat("a", 20),
		"risk-svcacct-" + strings.Repeat("a", 20),
		"task-ant-hill-clearance-report-final",
		"x" + "sk-ant-" + strings.Repeat("a", 20),
		"x" + "sk-ant-" + "report-final-version-2026-notes",
		"disk" + strings.Repeat("a1b2c3d4", 4),
		"SK" + strings.Repeat("a1b2c3d4", 5),
		"monkey-" + strings.Repeat("a1b2c3d4", 4),
		"key-" + strings.Repeat("a1b2c3d4", 5),
		"shipped 2026-12-30 23:59:59",
		"rendered 2006-01-02 15:04:05 UTC",
		"valid through 2026-05-26 23:59:59",
	}
	for _, text := range prose {
		t.Run(text, func(t *testing.T) {
			got := s.ScanTextForDLP(context.Background(), "note: "+text+" end")
			if !got.Clean || len(got.InformationalMatches) != 0 {
				t.Fatalf("prose produced a finding: enforced=%v informational=%v", gluedMatchNames(got.Matches), gluedMatchNames(got.InformationalMatches))
			}
		})
	}
}

type gluedBoundaryCase struct {
	name, pattern, prefix, secret string
	want                          bool
}

func gluedBoundaryCases() []gluedBoundaryCase {
	anthropic := gluedAnthropicKey()
	openai := "sk-" + "proj-" + strings.Repeat("Qw7eR9tY", 6)
	admin := "sk-" + "admin-" + strings.Repeat("Qw7eR9tY", 6)
	service := "sk-" + "svcacct-" + strings.Repeat("Qw7eR9tY", 6)
	mailgun := "key-" + strings.Repeat("a1b2c3d4", 4)
	twilio := "SK" + strings.Repeat("a1b2c3d4", 4)
	card := "4111" + strings.Repeat("1", 12)
	ssn := "123-45-" + "6789"
	github := "ghp_" + strings.Repeat("K", 36)
	aws := "AKIA" + strings.Repeat("V", 16)
	var cases []gluedBoundaryCase
	add := func(pattern, secret string, prefixes []string, want bool) {
		for _, prefix := range prefixes {
			name := pattern + "/prefix-" + prefixLabel(prefix)
			cases = append(cases, gluedBoundaryCase{name: name, pattern: pattern, prefix: prefix, secret: secret, want: want})
		}
	}
	for _, secret := range []struct{ pattern, value string }{
		{"Anthropic API Key", anthropic},
		{"OpenAI API Key", openai},
		{"OpenAI API Key", admin},
		{"OpenAI Service Key", service},
	} {
		add(secret.pattern, secret.value, []string{"x", "9", "_", "-"}, true)
	}
	for _, secret := range []struct{ pattern, value string }{
		{"Mailgun API Key", mailgun},
		{"Twilio API Key", twilio},
	} {
		add(secret.pattern, secret.value, []string{"x", "9", "_"}, true)
	}
	// A digit continues a card or an SSN, so that prefix stays a non-finding.
	// A letter or underscore is the one-character disguise.
	for _, secret := range []struct{ pattern, value string }{
		{"Credit Card Number", card},
		{"Social Security Number", ssn},
	} {
		add(secret.pattern, secret.value, []string{"x", "_"}, true)
		add(secret.pattern, secret.value, []string{"9"}, false)
	}
	add("GitHub Token", github, []string{"x"}, true)
	add("AWS Access ID", aws, []string{"x"}, true)
	return cases
}

func prefixLabel(prefix string) string {
	switch prefix {
	case "":
		return "none"
	case "_":
		return "underscore"
	case "-":
		return "hyphen"
	default:
		return prefix
	}
}

func gluedAnthropicKey() string {
	return "sk-" + "ant-" + "api03-" + strings.Repeat("Ab3dE6gH", 11) + "-xY" + "AA"
}

func gluedBoundaryScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 0
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxURLLength = 8192
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

// TestSavedOpenAIProjectBodyKeepsSingleCharacterGlue locks the previous
// project-only body. A preset saved before admin keys shared the rule still
// has to catch a project key glued to one character, and still has to ignore
// an admin-shaped value.
func TestSavedOpenAIProjectBodyKeepsSingleCharacterGlue(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.FetchProxy.Monitoring.SubdomainEntropyThreshold = 0
	cfg.FetchProxy.Monitoring.MaxReqPerMinute = 0
	cfg.FetchProxy.Monitoring.MaxURLLength = 8192
	legacy := config.ProviderKeyLeftBoundaryRegex + legacyOpenAIProjectKeyBody
	replaced := false
	for i, pattern := range cfg.DLP.Patterns {
		if pattern.Name != "OpenAI API Key" {
			continue
		}
		cfg.DLP.Patterns[i].Regex = legacy
		replaced = true
	}
	if !replaced {
		t.Fatal("OpenAI API Key pattern missing from defaults")
	}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	secret := "sk-" + "proj-" + strings.Repeat("Qw7eR9tY", 6)
	for _, prefix := range []string{"x", "9", "_", "-"} {
		text := "note: " + prefix + secret + " end"
		got := s.ScanTextForDLP(context.Background(), text)
		if !gluedBoundaryFound(got.Matches, got.InformationalMatches, "OpenAI API Key") {
			t.Fatalf("prefix %q: clean=%v matches=%v", prefix, got.Clean, gluedMatchNames(got.Matches))
		}
	}
	target := "https://api.vendor.example/v1/items?ref=" + url.QueryEscape("x"+secret)
	if result := s.Scan(context.Background(), target); !gluedBoundaryURLBlock(result, "OpenAI API Key") {
		t.Fatalf("URL allowed=%v scanner=%q", result.Allowed, result.Scanner)
	}
	admin := "note: " + "sk-" + "admin-" + strings.Repeat("Qw7eR9tY", 6) + " end"
	if got := s.ScanTextForDLP(context.Background(), admin); gluedBoundaryFound(got.Matches, got.InformationalMatches, "OpenAI API Key") {
		t.Fatal("legacy project body matched an admin-shaped value")
	}
}

func gluedBoundaryURLBlock(result Result, pattern string) bool {
	if result.Allowed || !strings.Contains(result.Reason, pattern) {
		return false
	}
	return result.Scanner == ScannerDLP || result.Scanner == ScannerCoreDLP
}

func gluedBoundaryFound(enforced, informational []TextDLPMatch, pattern string) bool {
	return matchHasPattern(enforced, pattern) || matchHasPattern(informational, pattern)
}

func matchHasPattern(matches []TextDLPMatch, pattern string) bool {
	for _, match := range matches {
		if match.PatternName == pattern {
			return true
		}
	}
	return false
}

func gluedMatchNames(matches []TextDLPMatch) []string {
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		names = append(names, match.PatternName)
	}
	return names
}

// A spaced letter-prefixed card is one finding. The source-confirmation guard
// drops the whitespace-joined copy, whose body is not contiguous in the source.
// Forcing gluedCandidateConfirmedInSource true reports that card twice.
func TestGluedCandidateConfirmedInSourceChangesCardCount(t *testing.T) {
	s := gluedBoundaryScanner(t)
	got := s.ScanTextForDLP(context.Background(), "a4111 1111 1111 1111")
	n := 0
	for _, match := range got.Matches {
		if match.PatternName == "Credit Card Number" {
			n++
		}
	}
	for _, match := range got.InformationalMatches {
		if match.PatternName == "Credit Card Number" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("spaced glued card findings = %d, want 1", n)
	}
}

// The zero-width-boundary families keep a shape gate after gaining a
// boundary-free body, and that gate admits each glued credential. A gate taken
// from the bounded grammar would refuse the glued Twilio key on word length.
func TestGluedBoundaryShapeGateAdmitsGluedCandidate(t *testing.T) {
	s := gluedBoundaryScanner(t)
	gated := map[string]bool{"Twilio API Key": true, "Social Security Number": true, "Credit Card Number": true}
	for _, p := range s.dlpPatterns {
		if !gated[p.name] {
			continue
		}
		delete(gated, p.name)
		if p.shapeGate == nil {
			t.Errorf("%s: shape gate dropped", p.name)
		}
	}
	for name := range gated {
		t.Errorf("%s: pattern not compiled", name)
	}
	for _, tc := range gluedBoundaryCases() {
		if !tc.want {
			continue
		}
		for _, p := range s.dlpPatterns {
			if p.name == tc.pattern && !p.admitsView("note: "+tc.prefix+tc.secret+" end") {
				t.Errorf("%s: shape gate refuses glued candidate %q", tc.pattern, tc.prefix)
			}
		}
	}
}
