// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"mime/quotedprintable"
	"net/url"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func prefixedCharacterCodes(text, prefix string, base int) string {
	var codes []string
	for _, r := range text {
		format := "%o"
		if base == 2 {
			format = "%b"
		}
		codes = append(codes, prefix+fmt.Sprintf(format, r))
	}
	return strings.Join(codes, ", ")
}

func mixedBase64Fixture(t *testing.T, text string) string {
	t.Helper()
	// Both non-shared alphabet symbols precede the protected value. Dropping
	// either as separator noise changes the following base64 quantum alignment.
	// Replacing '/' with '_' retains its six-bit value, so decoding still
	// yields the complete protected value, unlike arbitrary symbol replacement.
	value := base64.StdEncoding.EncodeToString([]byte("???~~~" + text))
	value = strings.ReplaceAll(value, "/", "_")
	if !strings.Contains(value, "+") || !strings.Contains(value, "_") {
		t.Fatal("fixture needs both alphabet families")
	}
	if _, err := base64.StdEncoding.DecodeString(value); err == nil {
		t.Fatal("standard fixture decoded")
	}
	if _, err := base64.URLEncoding.DecodeString(value); err == nil {
		t.Fatal("URL-safe fixture decoded")
	}
	return value
}

type textEncodingCase struct{ name, encoding, value string }

func textEncodingCases(t *testing.T, text string) []textEncodingCase {
	t.Helper()
	qp := strings.NewReplacer("-", "=2D", " ", "=20").Replace(text)
	qp = fmt.Sprintf("=%02X", text[0]) + qp[1:]
	return []textEncodingCase{
		{"decimal", encodingDecimal, decimalCharacterCodes(text, " ")},
		{"octal", encodingOctal, prefixedCharacterCodes(text, "0o", 8)},
		{"binary", encodingBinary, prefixedCharacterCodes(text, "0b", 2)},
		{"quoted printable", encodingQuotedPrintable, qp},
		{"soft CRLF", encodingQuotedPrintable, text[:3] + "=\r\n" + text[3:]},
		{"soft LF", encodingQuotedPrintable, text[:3] + "=\n" + text[3:]},
		{"mixed base64", encodingBase64, mixedBase64Fixture(t, text)},
	}
}

func TestTextEncodingCoverageDLP(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.FetchProxy.Monitoring.MaxURLLength = 4096
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	key := "xoxb-" + "1234567890abcdef"
	for _, tc := range textEncodingCases(t, key) {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Contains(tc.value, key) {
				t.Fatal("encoded fixture contains raw credential")
			}
			for _, padding := range []string{"", strings.Repeat("ordinary prose about a project. ", 700)} {
				for _, text := range []string{padding + tc.value, padding + base64.StdEncoding.EncodeToString([]byte(tc.value))} {
					result := s.ScanTextForDLP(t.Context(), text)
					found := false
					for _, m := range result.Matches {
						if m.PatternName == "Slack Token" {
							found = true
						}
					}
					if !found || result.Clean {
						t.Fatalf("credential was not detected: %+v", result)
					}
				}
			}
			found := false
			for _, d := range decodeEncodingsFixpoint(tc.value, true) {
				if d.encoding == tc.encoding && strings.Contains(d.text, key) {
					found = true
				}
			}
			if !found {
				t.Fatal("named decode view never exposed the credential")
			}
			result := s.Scan(t.Context(), "https://api.vendor.example/collect?data="+url.QueryEscape(tc.value))
			// URLs carrying a soft line break are already refused by the
			// earlier CRLF gate; text carriers exercise the decoded DLP view.
			if strings.Contains(tc.value, "\n") && !result.Allowed && result.Scanner == ScannerCRLF {
				return
			}
			if result.Allowed || (result.Scanner != ScannerDLP && result.Scanner != ScannerCoreDLP) {
				t.Fatalf("URL did not reach DLP detection: %+v", result)
			}
		})
	}
}

func TestTextEncodingCoverageInjection(t *testing.T) {
	for _, configured := range []bool{false, true} {
		cfg := testResponseConfig()
		phrase := testInjectionPhrase
		if configured {
			phrase = "indigo pelican carries a silver notebook"
			cfg.ResponseScanning.Patterns = []config.ResponseScanPattern{{Name: "custom encoded wording", Regex: phrase}}
		}
		s := MustNew(cfg)
		t.Cleanup(s.Close)
		for _, tc := range textEncodingCases(t, phrase) {
			t.Run(fmt.Sprintf("custom=%v/%s", configured, tc.name), func(t *testing.T) {
				if strings.Contains(tc.value, phrase) {
					t.Fatal("raw injection remained in fixture")
				}
				for _, padding := range []string{"", strings.Repeat("ordinary prose about a project. ", 700)} {
					result := s.ScanResponse(t.Context(), padding+tc.value)
					if result.Clean || result.Failed() || len(result.Matches) == 0 {
						t.Fatalf("no injection detection: %+v", result)
					}
				}
			})
		}
	}
}

func textEncodingHarmlessControls() []string {
	return []string{
		"1,2,3,4,5,6,7,8,9,10,255,255,255",
		"2026-01-02T12:34:56Z v1.2.3 10.20.30",
		"101 102 103 104 105 106 107 108",
		"0o10 0o11 0o12 0o13 0o14 0o15 0o16 0o17",
		"0b10 0b11 0b100 0b101 0b110 0b111 0b1000 0b1001",
		"Subject: project notes\r\n\r\nThe caf=C3=A9 meeting is at noon.\r\nPlease bring the note=\r\nbook.\r\nThanks.",
		base64.StdEncoding.EncodeToString([]byte("a harmless email attachment with ordinary prose")),
		"https://api.vendor.example/a%20document?label=hello%20world&value=42",
		"malformed =GG =x =+1 =\r and a trailing =",
	}
}

func TestTextEncodingCoverageControls(t *testing.T) {
	s := MustNew(testConfig())
	t.Cleanup(s.Close)
	for _, text := range textEncodingHarmlessControls() {
		t.Run(text, func(t *testing.T) {
			result := s.ScanTextForDLP(t.Context(), text)
			if !result.Clean || len(result.Matches) != 0 || len(result.InformationalMatches) != 0 {
				t.Fatalf("harmless control produced findings: %+v", result)
			}
			response := s.ScanResponse(t.Context(), text)
			if !response.Clean || response.Failed() {
				t.Fatalf("harmless response refused: %+v", response)
			}
		})
	}
}

func TestTextEncodingParsers(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"plain", "plain"},
		{"caf=C3=A9", "café"},
		{"a=\r\nb=\nc", "abc"},
		{"=GG=41=4a=", "=GGAJ="},
		{"=A?=41", "=A?A"},
		{"=+1=-1", "=+1=-1"},
		{"=0", "=0"},
	} {
		got, ranges := decodeQuotedPrintable(tc.input, true)
		if got != tc.want || got != tc.input && len(ranges) != len(got) {
			t.Fatalf("decode %q = %q, ranges=%d", tc.input, got, len(ranges))
		}
	}
	for _, encoding := range []string{encodingOctal, encodingBinary} {
		prefix, base := "0o", 8
		if encoding == encodingBinary {
			prefix, base = "0b", 2
		}
		codes := prefixedCharacterCodes("notebook", prefix, base)
		for _, tc := range []struct{ input, want string }{
			{codes, "notebook"},
			{prefixedCharacterCodes("notébook", prefix, base), "notébook"},
			{strings.ToUpper(codes), "notebook"},
			{codes + ", -1", "notebook"},
			{prefixedCharacterCodes("short", prefix, base), ""},
			{"0o999,0b222,0x41,0101,01000001,0o+1,0b_1", ""},
			{prefix + strings.Repeat("1", 40), ""},
		} {
			got, ranges := decodePrefixedCharacterCodes(tc.input, encoding, true)
			if got != tc.want || len(ranges) != len(got) {
				t.Fatalf("decode %q = %q", tc.input, got)
			}
		}
	}
}

func TestTextEncodingCoreAndKnownValues(t *testing.T) {
	cfg := testConfig()
	cfg.DLP.Patterns = nil
	cfg.DLP.ScanEnv = false
	core := MustNew(cfg)
	t.Cleanup(core.Close)
	for _, tc := range textEncodingCases(t, inspectionLimitAWSKey()) {
		t.Run("core/"+tc.name, func(t *testing.T) {
			result := core.ScanTextForDLP(t.Context(), tc.value)
			if result.Clean || len(result.Matches) == 0 || result.Matches[0].PatternName != patternNameAWSAccessID {
				t.Fatalf("core pattern was not detected: %+v", result)
			}
		})
	}
	canary := "planted-7F3a9c2e4b1d"
	secret := strings.Join([]string{"Z7pQ", "m2Lx8V4N9rW6"}, "-")
	known := numericChannelCanaryScanner(t, canary, secret)
	for _, value := range []string{canary, secret} {
		for _, tc := range textEncodingCases(t, value) {
			t.Run("known/"+tc.name+value[:1], func(t *testing.T) {
				result := known.ScanTextForDLP(t.Context(), tc.value)
				want := "Environment Variable Leak"
				if value == canary {
					want = "Canary Token (planted)"
				}
				found := false
				for _, match := range result.Matches {
					if match.PatternName == want {
						found = true
					}
				}
				if result.Clean || !found {
					t.Fatalf("known value was not detected: %+v", result)
				}
			})
		}
	}
}

func TestTextEncodingSourceRangesAndStrip(t *testing.T) {
	cfg := testResponseConfig()
	cfg.ResponseScanning.Action = config.ActionStrip
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range textEncodingCases(t, testInjectionPhrase) {
		t.Run(tc.name, func(t *testing.T) {
			source := "ordinary prefix\n" + tc.value + "\nordinary suffix"
			result := sc.ScanResponse(t.Context(), source)
			if result.Clean || result.TransformedContent != "" {
				t.Fatalf("encoded strip did not refuse: %+v", result)
			}
			for _, match := range result.Matches {
				if !match.hasDecodedSource || match.decodedSourceStart < len("ordinary prefix\n") || match.decodedSourceEnd > len(source)-len("\nordinary suffix") {
					t.Fatalf("decoded source range is missing or includes unrelated prose: %+v", match)
				}
				wantCross := strings.Contains(tc.value, "\n")
				if match.crossesFragmentBoundary != wantCross {
					t.Fatalf("boundary flag=%v want %v", match.crossesFragmentBoundary, wantCross)
				}
			}
			// Recursive range mapping must still index the outer source.
			nested := base64.StdEncoding.EncodeToString([]byte(tc.value))
			result = sc.ScanResponse(t.Context(), nested)
			if result.Clean {
				t.Fatal("nested encoding was not detected")
			}
			for _, match := range result.Matches {
				if !match.hasDecodedSource || match.decodedSourceStart < 0 || match.decodedSourceEnd > len(nested) {
					t.Fatal("nested source range is invalid")
				}
			}
		})
	}
}

func TestTextEncodingBudgetRefusal(t *testing.T) {
	sc := MustNew(testConfig())
	t.Cleanup(sc.Close)
	payload := "=41" + inspectionLimitAWSKey()[1:]
	for range 80 {
		payload = strings.ReplaceAll(payload, "=", "=3D")
	}
	text := strings.Repeat("!", 128*1024) + payload
	result := sc.ScanTextForDLP(t.Context(), text)
	if result.Clean || !HasInspectionLimit(result.Matches) {
		t.Fatalf("unfinished quoted-printable walk was not refused: clean=%v incomplete=%v", result.Clean, result.Incomplete)
	}
	if !sc.ScanTextForDLP(t.Context(), "a harmless =20 quoted-printable note").Clean {
		t.Fatal("one layer control refused")
	}
}

func TestTextEncodingNumberBoundaries(t *testing.T) {
	// This is an existing known-value view, but not a list of numeric literals.
	escaped := strings.Repeat(`\u0041`, 8)
	if decodeDecimalCharacterCodes(escaped) == "" {
		t.Fatal("known-value positive control stopped decoding")
	}
	for _, text := range []string{escaped, "word65word75word73word65word65word65word65word65"} {
		if got := appendTextEncodingViews(nil, text); len(got) != 0 {
			t.Fatalf("digits inside words manufactured %d views", len(got))
		}
	}
}

func TestTextEncodingQuotedPrintableProducer(t *testing.T) {
	sc := MustNew(testResponseConfig())
	t.Cleanup(sc.Close)
	for _, phrase := range []string{"xoxb-" + "1234567890abcdef", testInjectionPhrase} {
		var body bytes.Buffer
		writer := quotedprintable.NewWriter(&body)
		if _, err := writer.Write([]byte(strings.Repeat("a", 70) + phrase)); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body.String(), phrase) {
			t.Fatal("producer did not split the protected value")
		}
		if phrase == testInjectionPhrase {
			if result := sc.ScanResponse(t.Context(), body.String()); result.Clean || result.Failed() {
				t.Fatalf("producer wording not detected: %+v", result)
			}
		} else if result := sc.ScanTextForDLP(t.Context(), body.String()); result.Clean {
			t.Fatal("producer credential not detected")
		}
	}
}

func TestTextEncodingPreservesNormalizedBase64(t *testing.T) {
	sc := MustNew(testResponseConfig())
	t.Cleanup(sc.Close)
	encoded := base64.StdEncoding.EncodeToString([]byte(testInjectionPhrase))
	fullwidth := strings.Map(func(r rune) rune {
		if r >= '!' && r <= '~' {
			return r + 0xFEE0
		}
		return r
	}, encoded)
	result := sc.ScanResponse(t.Context(), "Report 20260102. "+fullwidth)
	if result.Clean || result.Failed() {
		t.Fatalf("normalized carrier was lost: %+v", result)
	}
}

func TestTextEncodingSourceRangeFailure(t *testing.T) {
	for _, inherited := range []bool{false, true} {
		for _, bounds := range [][2]int{{-1, 1}, {0, 0}, {2, 1}, {9, 10}} {
			match := ResponseMatch{
				span:             MatchSpan{ByteStart: bounds[0], ByteEnd: bounds[1], ViewLabel: ViewForMatching},
				hasDecodedSource: inherited, decodedSourceStart: bounds[0], decodedSourceEnd: bounds[1],
			}
			set := mapTextEncodingSources(responseMatchSet{matches: []ResponseMatch{match}}, "=61bc", decodedResult{"abc", encodingQuotedPrintable})
			if set.matches[0].hasDecodedSource {
				t.Fatal("unmappable inner offsets were retained as outer offsets")
			}
		}
	}
}

func TestTextEncodingCanaryQuotedPrintableSoftBreak(t *testing.T) {
	s := numericChannelCanaryScanner(t, "xyz12mnopq", "")
	for _, carrier := range []string{"xyz=31=\r\n=32mnopq", "xyz=31=\n=32mnopq"} {
		t.Run(fmt.Sprintf("%q", carrier), func(t *testing.T) {
			result := s.ScanTextForDLP(t.Context(), carrier)
			for _, match := range result.Matches {
				if match.PatternName == "Canary Token (planted)" && match.Encoded == encodingQuotedPrintable {
					return
				}
			}
			t.Fatalf("quoted-printable canary was not detected: %+v", result)
		})
	}
}

func TestTextEncodingNumericLineSeparators(t *testing.T) {
	canary := "xyz12mnopq"
	secret := strings.Join([]string{"fixture", "Q7m2X9z4R8v3N6p1"}, "-")
	sc := numericChannelCanaryScanner(t, canary, secret)
	for _, value := range []struct{ text, pattern string }{
		{canary, "Canary Token (planted)"},
		{secret, "Environment Variable Leak"},
		{"xoxb-" + "1234567890abcdef", "Slack Token"},
		{inspectionLimitAWSKey(), patternNameAWSAccessID},
	} {
		for _, carrier := range []string{
			decimalCharacterCodes(value.text, "\n"),
			strings.ReplaceAll(prefixedCharacterCodes(value.text, "0o", 8), ", ", "\n"),
			strings.ReplaceAll(prefixedCharacterCodes(value.text, "0b", 2), ", ", "\n"),
		} {
			t.Run(value.pattern+carrier[:2], func(t *testing.T) {
				result := sc.ScanTextForDLP(t.Context(), carrier)
				for _, match := range result.Matches {
					if match.PatternName == value.pattern {
						return
					}
				}
				t.Fatalf("line-separated character codes not detected: %+v", result)
			})
		}
	}
}
