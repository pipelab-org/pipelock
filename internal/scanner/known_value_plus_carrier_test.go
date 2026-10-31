// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func knownValuePlusScanner(t *testing.T, secret string) *Scanner {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig()
	cfg.DLP.ScanEnv = false
	cfg.DLP.IncludeDefaults = new(false)
	cfg.DLP.Patterns = nil
	cfg.DLP.SecretsFile = path
	s := MustNew(cfg)
	t.Cleanup(s.Close)
	return s
}

// Form decoding turns '+' into a space, so a nested carrier whose base64
// holds '+' as data must still decode from the raw or percent-decoded URL.
func TestKnownValueURLNestedCarrierKeepsPlus(t *testing.T) {
	secret := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1" // Synthetic; never a real credential.
	s := knownValuePlusScanner(t, secret)
	for _, prefix := range []string{"\xf8\xf8\xf8", "\xfb\xef"} {
		encoded := base64.StdEncoding.EncodeToString([]byte(prefix + hex.EncodeToString([]byte(secret))))
		if !strings.Contains(encoded, "+") {
			t.Fatalf("fixture %q carries no '+'", encoded)
		}
		for _, target := range []string{
			"https://example.test/p/" + encoded,
			"https://example.test/p#" + encoded,
			"https://example.test/p?q=" + url.QueryEscape(encoded),
		} {
			if got := s.Scan(t.Context(), target); got.Allowed {
				t.Errorf("%s: nested known value with '+' was allowed", target)
			}
		}
	}
	for _, target := range []string{"https://example.test/p/ordinary+path", "https://example.test/p?q=a+b"} {
		if got := s.Scan(t.Context(), target); !got.Allowed {
			t.Errorf("%s: control blocked: %s", target, got.Reason)
		}
	}
}

// A known value found only in a decoded view of text carries a label naming
// that view, and the reported encoding stays the encoding name.
func TestKnownValueDecodedTextViewLabels(t *testing.T) {
	secret := "Zq7Lm2Xc9Vb4" + "Nn8Kp3Rt6Wy1" // Synthetic; never a real credential.
	s := knownValuePlusScanner(t, secret)
	nested := func(prefix string) string {
		return base64.StdEncoding.EncodeToString([]byte(prefix + hex.EncodeToString([]byte(secret))))
	}
	plus := nested("\xf8\xf8\xf8")
	for _, tc := range []struct {
		name, body, view string
	}{
		// Repeated form decoding turns the escaped '+' into a space; the
		// RFC 3986 view keeps it.
		{"percent decoded", "note " + url.QueryEscape(plus), "percent_decoded"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.checkSecretsInTextWithDecodes(s.fileSecrets, tc.body, "Known secret", "", &decodingMemo{})
			if len(matches) != 1 {
				t.Fatalf("matches = %+v, want one", matches)
			}
			if label := matches[0].Span().ViewLabel; !strings.HasPrefix(label, ViewDLPNormalized+":"+tc.view+":") {
				t.Fatalf("view label = %q, want the %s view", label, tc.view)
			}
			if strings.Contains(matches[0].Encoded, "decoded") {
				t.Fatalf("encoded = %q, want the encoding name only", matches[0].Encoded)
			}
		})
	}
}

func TestRelabelKnownSecretViewsNamesSource(t *testing.T) {
	views := relabelKnownSecretViews([]spanTextView{{text: "x", viewLabel: dlpViewLabel("hex")}}, "url_decoded")
	if want := ViewDLPNormalized + ":url_decoded:hex"; views[0].viewLabel != want {
		t.Fatalf("label = %q, want %q", views[0].viewLabel, want)
	}
}
