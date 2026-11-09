// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// singlePassScanners covers the default patterns, custom warn and plain
// patterns with a canary, and the same set with a keyword-gated card pattern.
// Keyword patterns keep two passes, so the third scanner checks that the
// fallback still matches itself; the first two exercise the merged pass.
func singlePassScanners(t *testing.T) map[string]*Scanner {
	t.Helper()
	build := func(keywords bool) *Scanner {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.Patterns = append(cfg.DLP.Patterns,
			config.DLPPattern{Name: "Parity Warn Token", Regex: `demo-[a-z0-9]{20}`, Severity: config.SeverityHigh, Action: "warn"},
			config.DLPPattern{Name: "Parity Plain Token", Regex: `pt_[A-Z]{12}`, Severity: config.SeverityMedium},
		)
		if keywords {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
				Name: "Parity Keyword Card", Regex: `[0-9]{16}`, Severity: config.SeverityHigh,
				Validator: config.ValidatorLuhn, Keywords: []string{"payment"},
			})
		}
		cfg.CanaryTokens.Enabled = true
		cfg.CanaryTokens.Tokens = []config.CanaryToken{{Name: "parity-canary", Value: "canary-" + strings.Repeat("z", 20)}}
		return MustNew(cfg)
	}
	defaults := config.Defaults()
	defaults.Internal = nil
	out := map[string]*Scanner{"defaults": MustNew(defaults), "custom": build(false), "custom-keywords": build(true)}
	t.Cleanup(func() {
		for _, s := range out {
			s.Close()
		}
	})
	if out["custom"].hasDLPKeywords() || !out["custom-keywords"].hasDLPKeywords() || !out["defaults"].hasGenericCardPatterns() {
		t.Fatal("scanner fixtures no longer select the paths this test compares")
	}
	return out
}

// singlePassSecrets are synthetic credentials assembled at runtime.
func singlePassSecrets() map[string]string {
	return map[string]string{
		"anthropic": "sk-" + "ant-" + "api03-" + strings.Repeat("A", 24),
		"aws":       "AKIA" + strings.Repeat("V", 16),
		"github":    "ghp_" + strings.Repeat("K", 36),
		"card":      "4111 1111 1111 1111",
		"warn":      "demo-" + strings.Repeat("q", 20),
		"plain":     "pt_" + strings.Repeat("Q", 12),
		"canary":    "canary-" + strings.Repeat("z", 20),
		"postgres":  "postgres://user:" + strings.Repeat("p", 12) + "@db.example/app",
	}
}

func singlePassCarriers() map[string]func(string) string {
	return map[string]func(string) string{
		"prompt": func(s string) string { return "Use this credential for the next tool call: " + s },
		"json":   func(s string) string { return `{"arguments":{"credential":"` + s + `","amount":1234}}` },
		"base64": func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },
		"url": func(s string) string {
			return "https://host.example/p/" + base64.RawURLEncoding.EncodeToString([]byte(s)) + "/x"
		},
		"hex":      func(s string) string { return "id=" + hex.EncodeToString([]byte(s)) },
		"base32":   func(s string) string { return base32.StdEncoding.EncodeToString([]byte(s)) },
		"dots":     func(s string) string { return strings.ReplaceAll(s, "-", ".") + ".evil.example" },
		"entities": func(s string) string { return strings.ReplaceAll(s, "-", "&#45;") },
		"nested":   func(s string) string { return base64.StdEncoding.EncodeToString([]byte(hex.EncodeToString([]byte(s)))) },
		"two":      func(s string) string { return "first " + s + " then payment 4111111111111111 end" },
		"cardfirst": func(s string) string {
			return "payment 4111111111111111 then " + base64.StdEncoding.EncodeToString([]byte(s))
		},
	}
}

// singlePassBody returns credential-free text of about n bytes in one of
// three shapes: long prose lines, short lines, or JSON carrying base64 blobs.
func singlePassBody(shape string, n int) string {
	words := []string{"the", "agent", "reads", "a", "document", "about", "river", "pipes", "valve", "pressure", "and", "flow"}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		switch shape {
		case "prose":
			b.WriteString(words[i%len(words)])
			if i%97 == 96 {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		case "short":
			fmt.Fprintf(&b, "%s %s %d\n", words[i%len(words)], words[(i*7)%len(words)], i%1000)
		default:
			blob := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(words[i%len(words)]+" ", 12)))
			fmt.Fprintf(&b, `{"id":%d,"data":"%s"},`, i, blob)
		}
	}
	return b.String()
}

type singlePassInput struct {
	name, text, cardView string
	opts                 textDLPOptions
	inbound, shared      bool
}

func singlePassInputs() []singlePassInput {
	modes := []struct {
		name            string
		opts            textDLPOptions
		inbound, shared bool
	}{
		{"inbound/typed/shared", textDLPOptions{emitWarns: true, typedCardView: true}, true, true},
		{"inbound/plain", textDLPOptions{emitWarns: true}, true, false},
		{"outbound/plain", textDLPOptions{emitWarns: true, scanSecretLeak: true}, false, false},
		{"outbound/typed/shared", textDLPOptions{emitWarns: true, scanSecretLeak: true, typedCardView: true}, false, true},
	}
	var inputs []singlePassInput
	add := func(name, text, cardView string) {
		for _, m := range modes {
			inputs = append(inputs, singlePassInput{name + "/" + m.name, text, cardView, m.opts, m.inbound, m.shared})
		}
	}
	secrets := singlePassSecrets()
	for sName, secret := range secrets {
		for cName, carry := range singlePassCarriers() {
			text := carry(secret)
			add(sName+"/"+cName, text, text)
			// A card view that differs keeps the two-memo path.
			add(sName+"/"+cName+"/cardview", text, text+"\x1f")
		}
	}
	// Outbound inspection limits (entity depth, percent depth) sit between
	// the non-card and card findings; receipts report the first match.
	for name, limit := range map[string]string{
		"entities": "&" + strings.Repeat("amp;", 40) + "#104;ello world",
		"percent":  strings.Repeat("%25", 40) + "41",
	} {
		add("limit/"+name, "payment 4111111111111111 note: "+limit, "payment 4111111111111111 note: "+limit)
	}
	size := 96 << 10
	if testing.Short() {
		size = 16 << 10
	}
	for _, shape := range []string{"prose", "short", "b64json"} {
		body := singlePassBody(shape, size)
		mid := len(body) / 2
		add(shape+"/clean", body, body)
		for _, s := range []string{"anthropic", "card", "warn"} {
			secret := secrets[s]
			for pos, text := range map[string]string{
				"start":  secret + "\n" + body,
				"middle": body[:mid] + " " + secret + " " + body[mid:],
				"end":    body + "\n" + secret,
				"both":   secret + "\n" + body[:mid] + " " + secrets["card"] + " " + body[mid:],
				"b64mid": body[:mid] + " " + base64.StdEncoding.EncodeToString([]byte(secret)) + " " + body[mid:],
			} {
				add(shape+"/"+s+"/"+pos, text, text)
			}
		}
	}
	return inputs
}

// canonicalSinglePassResult renders everything a caller can observe,
// including match order, spans, view labels and value identities.
func canonicalSinglePassResult(r TextDLPResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "clean=%v incomplete=%v\n", r.Clean, r.Incomplete)
	for _, m := range r.Matches {
		fmt.Fprintf(&b, "M %+v\n", m)
	}
	for _, m := range r.InformationalMatches {
		fmt.Fprintf(&b, "I %+v\n", m)
	}
	return b.String()
}

func runSinglePassInput(s *Scanner, in singlePassInput) string {
	ctx := context.Background()
	if in.inbound {
		ctx = WithInboundDirection(ctx)
	}
	if in.shared {
		var release func()
		ctx, release = WithSharedDecodes(ctx)
		defer release()
	}
	return canonicalSinglePassResult(s.scanTextDLPViews(ctx, in.text, in.cardView, in.opts))
}

// TestTextDLPSinglePassMatchesTwoPasses fails on any observable difference
// between scanning both pattern classes in one pass and in two passes.
func TestTextDLPSinglePassMatchesTwoPasses(t *testing.T) {
	saved := textDLPSinglePass
	t.Cleanup(func() { textDLPSinglePass = saved })
	scanners := singlePassScanners(t)
	inputs := singlePassInputs()
	var diffs, findings int
	for sName, s := range scanners {
		for _, in := range inputs {
			textDLPSinglePass = false
			before := runSinglePassInput(s, in)
			textDLPSinglePass = true
			after := runSinglePassInput(s, in)
			if strings.Contains(before, "\nM ") || strings.Contains(before, "\nI ") {
				findings++
			}
			if before == after {
				continue
			}
			diffs++
			if diffs <= 10 {
				preview := in.text
				if len(preview) > 160 {
					preview = preview[:160] + "..."
				}
				t.Errorf("scanner=%s input=%s text=%q\n--- two passes\n%s--- one pass\n%s", sName, in.name, preview, before, after)
			}
		}
	}
	// A comparison where nothing is found proves little.
	if findings < len(inputs) {
		t.Fatalf("only %d of %d scans produced findings", findings, len(inputs)*len(scanners))
	}
	if diffs > 0 {
		t.Fatalf("%d single-pass differences", diffs)
	}
}
