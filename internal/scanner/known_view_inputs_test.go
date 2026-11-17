// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"math/rand/v2"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
)

// referenceCheckSecretsInRoots is checkSecretsInRoots before roots shared
// walked inputs: every root of the phase-one list is walked in full.
func referenceCheckSecretsInRoots(s *Scanner, secrets []string, roots knownSecretRoots, patternName, encodedOverride string, decodes *decodingMemo) []TextDLPMatch {
	if decodes.stopRequested() {
		return nil
	}
	original := roots.original
	// The memo's normalization records the scan's view ancestry; its value
	// equals the planned root.
	text := decodes.normalize(original)
	texts := []spanTextView{{text: text, viewLabel: ViewDLPNormalized}}
	lowerTexts := []spanTextView{{text: strings.ToLower(text), viewLabel: lowerViewLabel(ViewDLPNormalized)}}
	// Form decoding turns an escaped '+' into a space; the RFC 3986 view keeps
	// a known value that contains '+' whole.
	decoded, percent := roots.decoded, roots.percent
	if percent != text && percent != decoded {
		percentLabel := spanViewLabel(ViewDLPNormalized, "percent_decoded")
		texts = append(texts, spanTextView{text: percent, viewLabel: percentLabel})
		lowerTexts = append(lowerTexts, spanTextView{text: strings.ToLower(percent), viewLabel: lowerViewLabel(percentLabel)})
	}

	for phase := range 2 {
		if decodes.stopRequested() {
			return nil
		}
		if phase == 1 {
			texts = s.decodedKnownSecretViews(text, decodes)
			if original != text && (hasTextEncoding(original) || normalize.ContainsTags(original)) {
				texts = append(texts, s.decodedKnownSecretViews(original, decodes)...)
			}
			// URL serialization can escape a separator into path data. Split
			// the decoded view too, as known-value URL scanning already does.
			if decoded != text {
				texts = append(texts, relabelKnownSecretViews(s.decodedKnownSecretViews(decoded, decodes), "url_decoded")...)
			}
			// Form decoding turns an escaped '+' into a space; the RFC 3986
			// view keeps it as data.
			if percent != text && percent != decoded {
				texts = append(texts, relabelKnownSecretViews(s.decodedKnownSecretViews(percent, decodes), "percent_decoded")...)
			}
		}

		hits := newKnownValueWindowHits(texts)
		for _, secret := range secrets {
			if decodes.stopRequested() {
				return nil
			}
			var match knownSecretMatch
			var start, end int
			var viewLabel string
			var matched bool
			if phase == 0 {
				match, start, end, viewLabel, matched = matchSecretEncodingSpanWithHits(secret, s.knownSecretWindows[secret], s.knownSecretEncodings[secret], texts, lowerTexts, hits)
			} else {
				match, start, end, viewLabel, matched = matchDecodedKnownSecret(secret, s.knownSecretWindows[secret], texts, hits)
			}
			if matched {
				m := TextDLPMatch{PatternName: patternName, Severity: "critical", PartialLen: match.partialLen}
				if encodedOverride != "" {
					m.Encoded = encodedOverride
				} else {
					m.Encoded = match.encoding
					if m.Encoded == "" && phase == 1 {
						m.Encoded = strings.TrimPrefix(viewLabel, ViewDLPNormalized+":")
					}
					// The view's source names where the text came from, not
					// an encoding.
					for _, source := range []string{"url_decoded:", "percent_decoded:"} {
						m.Encoded = strings.TrimPrefix(m.Encoded, source)
					}
				}
				m.span = newMatchSpan(start, end, viewLabel, patternName, "", "")
				return []TextDLPMatch{m}
			}
		}
	}
	return nil
}

func knownViewInputsScanner(t *testing.T) (*Scanner, []string) {
	t.Helper()
	values := []string{"fileTok" + "Q7mZp2Lx9Vr4Tn8K", "keyVal" + "W3nB8cR1tY6uP0sD"}
	path := filepath.Join(t.TempDir(), "secrets")
	if err := os.WriteFile(path, []byte(strings.Join(values, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.SecretsFile = path
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, value := range values {
		if !slices.Contains(sc.fileSecrets, value) {
			t.Fatal("test values were not loaded")
		}
	}
	return sc, values
}

// Sharing walked inputs across the roots of one list reports the same match,
// span and view label as walking every root in full.
func TestKnownViewInputsMatchFullWalks(t *testing.T) {
	sc, values := knownViewInputsScanner(t)
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	rng := rand.New(rand.NewPCG(3, 5)) // #nosec G404 -- reproducible carrier corpus.
	pieces := []func(string) string{
		func(v string) string { return v },
		b64,
		func(v string) string { return hex.EncodeToString([]byte(v)) },
		url.QueryEscape,
		url.PathEscape,
		func(v string) string { return b64("prefix " + v[:18]) },
		func(v string) string { return base64.RawStdEncoding.EncodeToString([]byte("k="+v+" t")) + "*~" },
		func(v string) string { return strings.ReplaceAll(url.QueryEscape(v+" +"+v[:17]), "%", "%25") },
		// Escaped separators split only in the URL-decoded root, so these
		// segments exist under that root alone.
		func(v string) string { return "dir%2F" + b64(v) + "%2Fend" },
		func(v string) string { return "a%2F" + hex.EncodeToString([]byte(v)) },
		func(v string) string { return "k%3D" + b64("x "+v) + "%26z" },
		func(string) string { return "ordinary prose about release notes" },
		func(string) string { return "path/to%2Ffile+name%20here" },
		func(string) string { return b64("ordinary decoy text value") },
	}
	cases := 0
	for range 300 {
		var b strings.Builder
		for range 1 + rng.IntN(6) {
			value := values[rng.IntN(len(values))]
			if rng.IntN(3) > 0 {
				value = "neutral" + strings.Repeat("x", 20)
			}
			b.WriteString(pieces[rng.IntN(len(pieces))](value))
			b.WriteString([]string{" ", "\n", "&q=", "/", " %41 ", "+"}[rng.IntN(6)])
		}
		text := b.String()
		roots := newKnownSecretRoots(text)
		for _, secrets := range [][]string{sc.fileSecrets, values[:1], values[1:]} {
			want := referenceCheckSecretsInRoots(sc, secrets, roots, "Known Secret Leak", "", &decodingMemo{})
			got := sc.checkSecretsInRoots(secrets, roots, "Known Secret Leak", "", &decodingMemo{})
			if len(got) != len(want) {
				t.Fatalf("%q: shared walk %+v, full walks %+v", text, got, want)
			}
			for i := range got {
				if got[i].PatternName != want[i].PatternName || got[i].Encoded != want[i].Encoded || got[i].PartialLen != want[i].PartialLen || got[i].Span() != want[i].Span() {
					t.Fatalf("%q: shared walk %+v, full walks %+v", text, got[i], want[i])
				}
				if strings.Contains(got[i].Span().ViewLabel, ":") {
					cases++
				}
			}
		}
	}
	if cases < 50 {
		t.Fatalf("only %d phase-one matches; the fixture does not exercise shared roots", cases)
	}
}

// A repeated input is walked once per list, and again after the memo's
// incomplete state changes, because that state decides transferred credit.
func TestKnownViewInputsWalkOnceUnlessStateChanges(t *testing.T) {
	sc, values := knownViewInputsScanner(t)
	text := "carrier " + base64.StdEncoding.EncodeToString([]byte("k="+values[0])) + " tail"
	memo := &decodingMemo{}
	walked := make(knownViewInputs)
	first := sc.decodedKnownSecretViewsAfter(text, memo, walked)
	if len(first) == 0 {
		t.Fatal("fixture produced no views")
	}
	if again := sc.decodedKnownSecretViewsAfter(text, memo, walked); len(again) != 0 {
		t.Fatalf("repeated input produced %d views again", len(again))
	}
	memo.markIncomplete()
	if again := sc.decodedKnownSecretViewsAfter(text, memo, walked); len(again) == 0 {
		t.Fatal("input was not walked again after the incomplete state changed")
	}
	if fresh := sc.decodedKnownSecretViews(text, &decodingMemo{}); len(fresh) != len(first) {
		t.Fatalf("unshared walk produced %d views, shared first walk %d", len(fresh), len(first))
	}
}
