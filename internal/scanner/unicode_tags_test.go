// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func unicodeTags(text string) string {
	var b strings.Builder
	b.WriteRune(0xe0001)
	for _, r := range text {
		b.WriteRune(0xe0000 + r)
	}
	b.WriteRune(0xe007f)
	return b.String()
}

func tagForms(text string) []struct{ name, text string } {
	tags := unicodeTags(text)
	return []struct{ name, text string }{
		{"tags", tags},
		{"mixed", "visible prefix " + tags + " visible suffix"},
		{"interleaved", strings.Join(strings.Split(tags, ""), "\u200b")},
		{"base64 tags", base64.StdEncoding.EncodeToString([]byte(tags))},
		{"tags base64", unicodeTags(base64.StdEncoding.EncodeToString([]byte(text)))},
		{"mixed tags base64", "prefix " + unicodeTags(base64.StdEncoding.EncodeToString([]byte(text))) + " suffix"},
		{"mixed base64 tags", "prefix " + base64.StdEncoding.EncodeToString([]byte(tags)) + " suffix"},
		{"hex tags", hex.EncodeToString([]byte(tags))},
	}
}

func tagsScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := testResponseConfig()
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxURLLength = 16000
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

func TestUnicodeTagsDLP(t *testing.T) {
	s := tagsScanner(t)
	key := inspectionLimitAWSKey()
	for _, form := range tagForms(key) {
		t.Run(form.name, func(t *testing.T) {
			for surface, result := range map[string]TextDLPResult{
				"text":  s.ScanTextForDLP(t.Context(), form.text),
				"body":  s.ScanRequestBodyTextForDLP(t.Context(), `{"note":"`+form.text+`"}`),
				"quiet": s.ScanTextForDLPQuiet(t.Context(), form.text),
			} {
				if result.Clean || result.Incomplete {
					t.Fatalf("%s clean=%v incomplete=%v", surface, result.Clean, result.Incomplete)
				}
				found := false
				for _, m := range result.Matches {
					if strings.Contains(m.PatternName, "AWS Access ID") && m.Encoded != "" && m.Span().Valid() && m.Span().ViewLabel != ViewDLPNormalized {
						if form.name == "tags" && (m.Encoded != encodingUnicodeTags || !strings.Contains(m.Span().ViewLabel, encodingUnicodeTags)) {
							t.Fatalf("%s: wrong tag view metadata: %+v", surface, m)
						}
						found = true
					}
				}
				if !found {
					t.Fatalf("%s missing decoded AWS evidence: %+v", surface, result.Matches)
				}
			}
			for location, target := range map[string]string{"query": "https://api.vendor.example/?q=" + url.QueryEscape(form.text), "path": "https://api.vendor.example/" + url.PathEscape(form.text)} {
				result := s.Scan(t.Context(), target)
				if result.Allowed || (result.Scanner != ScannerDLP && result.Scanner != ScannerCoreDLP) {
					t.Errorf("%s allowed=%v scanner=%s reason=%s", location, result.Allowed, result.Scanner, result.Reason)
				}
				if spans := result.Spans(); len(spans) == 0 || !spans[0].Valid() || form.name == "tags" && !strings.Contains(spans[0].ViewLabel, encodingUnicodeTags) {
					t.Errorf("%s missing decoded URL evidence: %+v", location, spans)
				}
			}
		})
	}
	if got := s.ScanTextForDLP(t.Context(), key[:4]+unicodeTags("ordinary")+key[4:]); got.Clean {
		t.Fatal("lost stripped view")
	}
}

func TestUnicodeTagsKnownValues(t *testing.T) {
	secret := "Zq7Lm2Xc9" + "Vb4Nn8Kp3Rt6Wy1"
	for _, source := range []string{"file", "env", "canary"} {
		t.Run(source, func(t *testing.T) {
			var s *Scanner
			pattern := "Known Secret Leak"
			switch source {
			case "file":
				s = knownSecretEncodingScanner(t, []string{secret})
			case "env":
				t.Setenv("PIPELOCK_TAG_TEST_SECRET", secret)
				cfg := testConfig()
				cfg.DLP.ScanEnv = true
				s = MustNew(cfg)
				t.Cleanup(s.Close)
				pattern = "Environment Variable Leak"
			case "canary":
				cfg := testConfig()
				cfg.DLP.ScanEnv = false
				cfg.CanaryTokens = config.CanaryTokens{Enabled: true, Tokens: []config.CanaryToken{{Name: "sample", Value: secret}}}
				s = MustNew(cfg)
				t.Cleanup(s.Close)
				pattern = "Canary Token"
			}
			s.maxURLLength = 16000
			s.entropyThreshold = 0
			for _, form := range tagForms(secret) {
				t.Run(form.name, func(t *testing.T) {
					result := s.ScanTextForDLP(t.Context(), form.text)
					found := false
					for _, m := range result.Matches {
						if strings.Contains(m.PatternName, pattern) && m.Span().Valid() && m.Span().ViewLabel != ViewDLPNormalized {
							found = true
						}
					}
					if result.Clean || !found {
						t.Fatalf("missing %s decoded match: %+v", source, result.Matches)
					}
					for _, target := range []string{"https://api.vendor.example/?q=" + url.QueryEscape(form.text), "https://api.vendor.example/" + url.PathEscape(form.text)} {
						if got := s.Scan(t.Context(), target); got.Allowed || (got.Scanner != ScannerDLP && got.Scanner != ScannerCoreDLP) {
							t.Fatalf("URL allowed=%v scanner=%s", got.Allowed, got.Scanner)
						}
					}
				})
			}
		})
	}
}

func TestUnicodeTagsInjection(t *testing.T) {
	s := tagsScanner(t)
	for _, form := range tagForms(testInjectionPhrase) {
		t.Run(form.name, func(t *testing.T) {
			for surface, result := range map[string]ResponseScanResult{
				"text": s.ScanResponse(t.Context(), form.text),
				"body": s.ScanResponseBodyWithSuppress(t.Context(), []byte(form.text), "", nil),
			} {
				if result.Clean || result.Failed() || len(result.Matches) == 0 {
					t.Fatalf("%s clean=%v error=%s", surface, result.Clean, result.ScanError)
				}
				if !strings.Contains(result.Matches[0].Span().ViewLabel, "decoded") {
					t.Fatalf("missing decoded evidence: %+v", result.Matches)
				}
			}
			if got := s.ScanCoreResponse(t.Context(), form.text); len(got) == 0 {
				t.Fatal("missing core injection")
			}
		})
	}
}

func TestUnicodeTagsHarmless(t *testing.T) {
	s := tagsScanner(t)
	for _, text := range []string{"ordinary prose", "正常な文章", "\U0001f3f4" + unicodeTags("gbeng"), "prefix " + unicodeTags("a harmless note") + " suffix", unicodeTags(""), unicodeTags(strings.Repeat("!", maxDecodeTotalBytes/4+1)), strings.Repeat("\U000e0000", maxDecodeTotalBytes/4+1)} {
		if got := s.ScanTextForDLP(t.Context(), text); !got.Clean || got.Incomplete {
			t.Fatalf("harmless DLP clean=%v incomplete=%v matches=%v", got.Clean, got.Incomplete, matchNames(got.Matches))
		}
		if got := s.ScanResponse(t.Context(), text); !got.Clean || got.Failed() {
			t.Fatalf("harmless response clean=%v error=%s", got.Clean, got.ScanError)
		}
	}
}

func TestUnicodeTagsConfiguredViews(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Sample Marker", Regex: `sample-marker-[0-9]{6}`, Severity: config.SeverityHigh}}
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "Sample Directive", Regex: `follow the sapphire protocol`}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	s.core = nil // Isolate configurable matchers from the immutable floor.
	if got := s.ScanTextForDLP(t.Context(), unicodeTags("sample-marker-"+"123456")); got.Clean {
		t.Fatal("configured DLP missed tag view")
	}
	if got := s.ScanResponse(t.Context(), unicodeTags("follow the sapphire protocol")); got.Clean {
		t.Fatal("configured injection missed tag view")
	}
}

func TestUnicodeTagsDecodeBudget(t *testing.T) {
	s := tagsScanner(t)
	result := s.ScanTextForDLP(t.Context(), unicodeTags(decodeBudgetNestedText()))
	if result.Clean || !HasInspectionLimit(result.Matches) {
		t.Fatalf("expected decode limit refusal: clean=%v matches=%v", result.Clean, matchNames(result.Matches))
	}
}

func TestUnicodeTagsStripRetainsRefusal(t *testing.T) {
	s := tagsScanner(t)
	s.responseAction = config.ActionStrip
	for _, form := range tagForms(testInjectionPhrase) {
		result := s.ScanResponse(t.Context(), form.text)
		if result.Clean || result.TransformedContent != "" {
			t.Fatalf("%s must remain detection-only: clean=%v rewritten=%v", form.name, result.Clean, result.TransformedContent != "")
		}
	}
}

func TestUnicodeTagsAssessment(t *testing.T) {
	s := tagsScanner(t)
	for _, tc := range []struct {
		text   string
		status AssessmentStatus
		blank  bool
	}{
		{unicodeTags("ordinary response"), AssessmentBenign, false},
		{unicodeTags(testInjectionPhrase), AssessmentFinding, false},
		{unicodeTags(""), AssessmentNotAssessed, true},
	} {
		if blank := IsBlankInjectionView(tc.text); blank != tc.blank {
			t.Fatalf("blank=%v want=%v", blank, tc.blank)
		}
		for _, result := range []ResponseScanResult{s.ScanResponse(t.Context(), tc.text), s.ScanResponseBodyWithSuppress(t.Context(), []byte(tc.text), "", nil)} {
			if result.Assessment.Status != tc.status {
				t.Fatalf("assessment=%s want=%s", result.Assessment.Status, tc.status)
			}
		}
	}
}

func TestUnicodeTagsInjectionStrippedEncoding(t *testing.T) {
	s := tagsScanner(t)
	encoded := base64.StdEncoding.EncodeToString([]byte(testInjectionPhrase))
	for _, tag := range []string{"\U000e0000", unicodeTags("ordinary")} {
		text := encoded[:2] + tag + encoded[2:]
		if got := s.ScanResponse(t.Context(), text); got.Clean || got.Failed() {
			t.Fatalf("stripped encoding was lost: clean=%v error=%s", got.Clean, got.ScanError)
		}
	}
}

func TestUnicodeTagsInjectionVariantViews(t *testing.T) {
	s := tagsScanner(t)
	for _, tc := range []struct{ name, text, view string }{
		{"spaced", strings.ReplaceAll(unicodeTags(testInjectionPhrase), "\U000e0020", "\u200b"), "invisible_spaced:for_matching:unicode_tags_decoded"},
		{"vowel folded", unicodeTags(strings.ReplaceAll(testInjectionPhrase, "e", "o")), "vowel_fold:for_matching:unicode_tags_decoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := s.ScanResponse(t.Context(), tc.text)
			if got.Clean || got.Failed() || len(got.Matches) == 0 || got.Matches[0].Span().ViewLabel != tc.view {
				t.Fatalf("clean=%v error=%s matches=%+v", got.Clean, got.ScanError, got.Matches)
			}
		})
	}
}

func TestUnicodeTagsSeed(t *testing.T) {
	s := tagsScanner(t)
	phrase := strings.Repeat("abandon ", 11) + "about"
	for _, form := range tagForms(phrase) {
		t.Run(form.name, func(t *testing.T) {
			got := s.ScanTextForDLP(t.Context(), form.text)
			found := false
			for _, m := range got.Matches {
				found = found || m.PatternName == "BIP-39 Seed Phrase"
			}
			if got.Clean || !found {
				t.Fatalf("missing decoded seed finding: clean=%v matches=%v", got.Clean, matchNames(got.Matches))
			}
		})
	}
}
