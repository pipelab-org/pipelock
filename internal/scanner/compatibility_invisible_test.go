// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

func TestResponseCompatibilityFoldedInvisibles(t *testing.T) {
	for _, plain := range []string{testInjectionPhrase, "normalization witness"} {
		t.Run(plain, func(t *testing.T) {
			cfg := testResponseConfig()
			cfg.ResponseScanning.Action = config.ActionStrip
			cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns,
				config.ResponseScanPattern{Name: "Normalization witness", Regex: "normalization witness"})
			s := MustNew(cfg)
			t.Cleanup(s.Close)
			const prefix, suffix = "前 \uFFA0ok \u1e9e ", " 後"
			interleaved := strings.Join(strings.Split(plain, ""), "\uFFA0") + "\uFFA0"
			input := prefix + interleaved + suffix
			result := s.ScanResponse(t.Context(), input)
			if result.Clean || len(result.Matches) == 0 {
				t.Fatalf("expected wording match: %+v", result)
			}
			for _, match := range result.Matches {
				if span := match.Span(); span.ViewLabel != ViewForMatching {
					t.Fatalf("unexpected span view: %+v", span)
				}
				assertSpanSlice(t, normalize.ForMatching(input), match.Span(), plain)
				start, end, ok := normalizedMatchSourceRange(input, match)
				if !ok || input[start:end] != interleaved {
					t.Fatalf("source mapping = [%d:%d], valid=%v, want original wording", start, end, ok)
				}
			}
			if !strings.HasPrefix(result.TransformedContent, prefix) || !strings.HasSuffix(result.TransformedContent, suffix) {
				t.Fatalf("strip changed surrounding bytes: %q", result.TransformedContent)
			}
			if !s.ScanResponse(t.Context(), result.TransformedContent).Clean {
				t.Fatal("stripped content retained a finding")
			}
		})
	}
}

func TestDLPCompatibilityFoldedInvisibles(t *testing.T) {
	cfg := testConfig()
	cfg.FetchProxy.Monitoring.MaxURLLength = config.Defaults().FetchProxy.Monitoring.MaxURLLength
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	credential := testAnthropicPrefix + strings.Repeat("a", 25)
	interleaved := strings.Join(strings.Split(credential, ""), "\uFFA0")
	text := "前 \uFFA0ok " + interleaved + " 後"
	t.Run("text", func(t *testing.T) {
		result := s.ScanTextForDLP(t.Context(), text)
		if result.Clean {
			t.Fatal("expected text DLP finding")
		}
		for _, match := range result.Matches {
			if match.PatternName == testAnthropicName {
				assertSpanSlice(t, normalize.ForDLP(text), match.Span(), credential)
				return
			}
		}
		t.Fatalf("missing provider finding: %+v", result.Matches)
	})
	t.Run("url", func(t *testing.T) {
		result := s.Scan(t.Context(), "https://api.vendor.example/?value="+url.QueryEscape(text))
		if result.Allowed || (result.Scanner != ScannerDLP && result.Scanner != ScannerCoreDLP) {
			t.Fatalf("expected URL DLP finding: %+v", result)
		}
		assertSpanSlice(t, normalize.ForDLP("value="+text), onlyResultSpan(t, result), credential)
	})
}

func TestResponseCompatibilityFoldedSeparator(t *testing.T) {
	// A literal inter-word space has no optional-whitespace variant, so only
	// the spaced view can restore the boundary a folded separator replaced.
	cfg := testResponseConfig()
	cfg.ResponseScanning.Action = config.ActionStrip
	cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "Normalization witness", Regex: "normalization witness"}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	const prefix, suffix, wording = "前 ok ", " 後", "normalizationﾠwitness"
	input := prefix + wording + suffix
	result := s.ScanResponse(t.Context(), input)
	if result.Clean || len(result.Matches) != 1 {
		t.Fatalf("expected one wording match: %+v", result)
	}
	match := result.Matches[0]
	if span := match.Span(); span.ViewLabel != ViewInvisibleSpaced {
		t.Fatalf("unexpected span view: %+v", span)
	}
	assertSpanSlice(t, normalize.ForMatchingSpaced(input), match.Span(), "normalization witness")
	start, end, ok := normalizedMatchSourceRange(input, match)
	if !ok || input[start:end] != wording {
		t.Fatalf("source mapping = [%d:%d], valid=%v, want original wording", start, end, ok)
	}
	if result.TransformedContent != prefix+"[REDACTED: Normalization witness]"+suffix {
		t.Fatalf("strip result = %q", result.TransformedContent)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(wording))
	if s.ScanResponse(t.Context(), encoded).Clean {
		t.Fatal("expected decoded wording match")
	}
}
