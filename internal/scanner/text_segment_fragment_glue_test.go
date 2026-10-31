// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The encoded-value decoders drop bytes outside their alphabet, so a '#'
// inside one encoded token must not stop the whole token from decoding. The
// '#' split adds the pieces beside each segment; it must not replace it.
func TestTextDLPSegmentsKeepWholeSegmentAroundFragmentDelimiter(t *testing.T) {
	glued := func(secret string, cut int) string {
		encoded := base64.StdEncoding.EncodeToString([]byte(secret))
		return `{"note":"` + encoded[:cut] + "#" + encoded[cut:] + `","id":"ordinary words here"}`
	}

	// A configured pattern the immutable core floor does not cover.
	s := MustNew(testConfig())
	t.Cleanup(s.Close)
	// A documented example key shape the core floor covers.
	cfg := testConfig()
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	core := MustNew(cfg)
	t.Cleanup(core.Close)
	for _, cut := range []int{13, 16, 22} {
		if got := s.ScanTextForDLP(t.Context(), glued(testAnthropicPrefix+strings.Repeat("c", 25), cut)); got.Clean {
			t.Errorf("cut %d: pattern DLP missed a base64 secret split by '#'", cut)
		}
		if got := core.ScanTextForDLP(t.Context(), glued("AKIA"+"IOSFODNN7EXAMPLE", cut)); got.Clean {
			t.Errorf("cut %d: core DLP floor missed a base64 secret split by '#'", cut)
		}
	}
}

func TestKnownValuesKeepWholeSegmentAroundFragmentDelimiter(t *testing.T) {
	secret := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1" // Synthetic; never a real credential.
	marker := "glue-canary-" + "fixture-0123456789"
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	cfg.DLP.SecretsFile = path
	cfg.CanaryTokens.Enabled = true
	cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "glue-fixture", Value: marker}}
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	for _, value := range []string{secret, marker} {
		encoded := base64.StdEncoding.EncodeToString([]byte(value))
		for _, cut := range []int{13, 16, 22} {
			body := `{"note":"` + encoded[:cut] + "#" + encoded[cut:] + `","id":"ordinary words here"}`
			if got := s.ScanTextForDLP(t.Context(), body); got.Clean {
				t.Errorf("%.6s cut %d: known value split by '#' was missed", value, cut)
			}
		}
	}
}

func TestTextDLPSegmentsKeepsWholeSegmentFirst(t *testing.T) {
	got := textDLPSegments(`a "b#c" d#d`)
	want := []string{"a", "b#c", "b", "c", "d#d", "d"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("segments = %q, want %q", got, want)
	}
}
