// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestURLTextSegmentsKnownValues(t *testing.T) {
	secret := "synthetic-" + "credential-value-42"
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil // These tests use only loopback destinations, without DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)

	for _, encoding := range []struct {
		name   string
		encode func(string) string
	}{
		{"base64", func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }},
		{"hex", func(s string) string { return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s)))) }},
	} {
		t.Run(encoding.name, func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				value string
				clean bool
			}{
				{"ordinary", "ordinary", true},
				{"encoded ordinary", encoding.encode("note:ordinary"), true},
				{"configured", encoding.encode("note:" + secret), false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					raw := "http://127.0.0.1/receive#" + tc.value
					parsed, err := url.ParseRequestURI(raw)
					if err != nil {
						t.Fatal(err)
					}
					for _, value := range []string{raw, parsed.String()} {
						if got := sc.Scan(t.Context(), value); got.Allowed != tc.clean {
							t.Errorf("URL allowed=%t, want %t", got.Allowed, tc.clean)
						}
						if got := sc.ScanTextForDLP(t.Context(), value); got.Clean != tc.clean {
							t.Errorf("text clean=%t, want %t", got.Clean, tc.clean)
						}
					}
				})
			}
		})
	}
}

func TestURLTextSegmentsDLP(t *testing.T) {
	cfg := config.Defaults()
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: "SYNTHETIC_VALUE_[0-9]+", Severity: config.SeverityCritical}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name, value string
		clean       bool
	}{
		{"ordinary", "ordinary", true},
		{"encoded ordinary", "note:ordinary", true},
		{"pattern", "note:SYNTHETIC_VALUE_42", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := "https://example.com/page#" + hex.EncodeToString([]byte(tc.value))
			if got := sc.ScanTextForDLP(t.Context(), value); got.Clean != tc.clean {
				t.Errorf("text clean=%t, want %t", got.Clean, tc.clean)
			}
		})
	}
}

func TestURLTextSegmentsPatternPath(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil // These tests use only loopback destinations, without DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: "SYNTHETIC_VALUE_[0-9]+", Severity: config.SeverityCritical}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, encoding := range []struct {
		name   string
		encode func(string) string
	}{
		{"hex", func(s string) string { return hex.EncodeToString([]byte(s)) }},
		{"hex base64", func(s string) string { return hex.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(s)))) }},
	} {
		t.Run(encoding.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, value string
				clean       bool
			}{
				{"ordinary", "note:ordinary", true},
				{"pattern", "note:SYNTHETIC_VALUE_42", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					// A server-parsed request target keeps '#' in the path;
					// serializing it escapes the separator.
					parsed, err := url.ParseRequestURI("http://127.0.0.1/receive#" + encoding.encode(tc.value))
					if err != nil {
						t.Fatal(err)
					}
					if got := sc.Scan(t.Context(), parsed.String()); got.Allowed != tc.clean {
						t.Errorf("URL allowed=%t, want %t: %s", got.Allowed, tc.clean, got.Reason)
					}
				})
			}
		})
	}
}

// RFC 3986 percent-encoding has no plus-as-space rule; only form-encoded
// queries map '+' to a space. Fragment and path decoding must keep '+' as data.
func TestURLTextSegmentsPlusIsData(t *testing.T) {
	const pattern = "SYNTHETIC+VALUE_42"
	secret := "Zq7Lm2+Xc9Vb4" + "Nn8Kp3Rt6Wy1" // Synthetic; never a real credential.
	path := filepath.Join(t.TempDir(), "values")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil // These tests use only loopback destinations, without DNS.
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "synthetic value", Regex: `SYNTHETIC\+VALUE_[0-9]+`, Severity: config.SeverityCritical}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	sc.entropyThreshold = 0 // Isolate DLP from the separate entropy policy.

	// Escape every byte after the first plus, so each carrier mixes a raw
	// '+' with bytes that need more than one decoding round.
	escapeTail := func(s, prefix string) string {
		i := strings.IndexByte(s, '+') + 1
		var b strings.Builder
		b.WriteString(s[:i])
		for _, c := range []byte(s[i:]) {
			fmt.Fprintf(&b, "%s%02X", prefix, c)
		}
		return b.String()
	}
	forms := []struct {
		name   string
		encode func(string) string
	}{
		{"raw", func(s string) string { return s }},
		{"escaped", func(s string) string { return strings.ReplaceAll(s, "+", "%2B") }},
		{"double escaped", func(s string) string { return strings.ReplaceAll(s, "+", "%252B") }},
		{"plus beside double escaped", func(s string) string { return escapeTail(s, "%25") }},
		{"plus beside triple escaped", func(s string) string { return escapeTail(s, "%2525") }},
	}
	for _, value := range []struct{ name, text string }{{"pattern", pattern}, {"known value", secret}} {
		for _, form := range forms {
			for _, place := range []struct{ name, prefix string }{
				{"fragment", "http://127.0.0.1/receive#"},
				{"path", "http://127.0.0.1/receive/"},
			} {
				t.Run(value.name+"/"+form.name+"/"+place.name, func(t *testing.T) {
					target := place.prefix + form.encode(value.text)
					if got := sc.Scan(t.Context(), target); got.Allowed || got.Scanner != ScannerDLP {
						t.Errorf("%s allowed=%t scanner=%s", target, got.Allowed, got.Scanner)
					}
				})
			}
		}
	}

	// A base64 carrier whose alphabet includes '+', glued to a byte that
	// needs two decoding rounds, inside one path or fragment segment.
	for _, tc := range []struct {
		name, value string
		clean       bool
	}{
		{"ordinary", "note:ordinary-documentation", true},
		{"configured", "note:" + secret, false},
		{"pattern", "note:" + pattern, false},
	} {
		// "\xf8\xf8\xf8" encodes as "+Pj4". A space in place of that plus
		// shifts every later symbol, even when the space splits the segment.
		encoded := base64.StdEncoding.EncodeToString([]byte("\xf8\xf8\xf8" + tc.value))
		if !strings.Contains(encoded, "+") {
			t.Fatalf("%s carrier %q lacks the plus this case needs", tc.name, encoded)
		}
		carrier := fmt.Sprintf("%%25%02X", encoded[0]) + encoded[1:]
		for _, prefix := range []string{"http://127.0.0.1/receive#", "http://127.0.0.1/receive/"} {
			t.Run("base64/"+tc.name+"/"+prefix[len(prefix)-1:], func(t *testing.T) {
				if got := sc.Scan(t.Context(), prefix+carrier); got.Allowed != tc.clean || (!tc.clean && got.Scanner != ScannerDLP) {
					t.Errorf("allowed=%t want %t: %s", got.Allowed, tc.clean, got.Reason)
				}
			})
		}
	}
}

func seedURLScanner(t *testing.T) *Scanner {
	t.Helper()
	cfg := testConfig()
	cfg.Internal = nil // Seed detection runs before DNS; keep the test offline.
	cfg.SeedPhraseDetection.Enabled = ptrBool(true)
	cfg.SeedPhraseDetection.MinWords = 12
	cfg.SeedPhraseDetection.VerifyChecksum = ptrBool(true)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	return sc
}

func requireSeedVerdict(t *testing.T, sc *Scanner, target string, blocked bool) {
	t.Helper()
	got := sc.Scan(t.Context(), target)
	if got.Allowed == blocked {
		t.Fatalf("%s allowed=%t want %t: %s", target, got.Allowed, !blocked, got.Reason)
	}
	if blocked && !strings.Contains(got.Reason, "Seed Phrase") {
		t.Fatalf("%s blocked for %q, want a seed phrase", target, got.Reason)
	}
}

// Only the fragment carries the seed, so fragment views must reach seed
// detection on their own.
func TestURLTextSegmentsSeedPhraseInFragment(t *testing.T) {
	sc := seedURLScanner(t)
	ordinary := strings.Repeat("ordinary_", 11) + "words"
	requireSeedVerdict(t, sc, "https://api.vendor.example/receive#"+ordinary, false)
	requireSeedVerdict(t, sc, "https://api.vendor.example/receive#"+strings.ReplaceAll(testSeedPhrase12, " ", "_"), true)
}

// An escaped '#' stays in the parsed path and glues a non-alphabet prefix to
// the encoded seed, so the segment must also be tried in pieces around it.
func TestURLTextSegmentsSeedPhraseAfterEscapedFragmentDelimiter(t *testing.T) {
	sc := seedURLScanner(t)
	for _, tc := range []struct {
		name, text string
		blocked    bool
	}{
		{"ordinary", strings.Repeat("ordinary ", 11) + "words", false},
		{"seed", testSeedPhrase12, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 'x' is base64 data, so dropping only the '#' misaligns the decode.
			target := "https://api.vendor.example/x%23" + base64.StdEncoding.EncodeToString([]byte(tc.text))
			requireSeedVerdict(t, sc, target, tc.blocked)
		})
	}
}
