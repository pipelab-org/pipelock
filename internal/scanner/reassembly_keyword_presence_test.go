// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyKeywordPresence(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: keywordPattern, Regex: `[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}})
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	data := make([]byte, 256<<10)
	r := rand.New(rand.NewSource(1)) // #nosec G404 -- deterministic admission corpus.
	for i := range data {
		data[i] = "0123456789"[r.Intn(10)]
	}
	split := func(text string) string {
		var b strings.Builder
		for i := 0; i < len(text); i += 40 {
			if i > 0 {
				b.WriteByte('!')
			}
			b.WriteString(text[i:min(i+40, len(text))])
		}
		return b.String()
	}
	for name, encode := range map[string]func([]byte) string{"hex": hex.EncodeToString, "base64": base64.StdEncoding.EncodeToString} {
		body := split(encode(data))
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, inbound := range []bool{false, true} {
				ctx := context.Background()
				if inbound {
					ctx = WithInboundDirection(ctx)
				}
				result := sc.ScanTextForDLP(ctx, body)
				if !result.Clean || len(result.Matches) != 0 {
					t.Fatalf("unlabeled encoded records, inbound=%v: %+v", inbound, result.Matches)
				}
				// A label in the decoded lane must retain its exact proximity semantics.
				result = sc.ScanTextForDLP(ctx, split(encode([]byte("lookup "+keywordNumber+strings.Repeat("x", 6000)))))
				if !keywordFound(result) || HasInspectionLimit(result.Matches) {
					t.Fatalf("labeled encoded record, inbound=%v: %+v", inbound, result.Matches)
				}
			}
		})
	}
}

func TestReassemblyKeywordPresenceReuse(t *testing.T) {
	sc := keywordScanner(t, []string{"~~~"}, 10)
	t.Cleanup(sc.Close)
	body := reassemblyBang(hex.EncodeToString([]byte(strings.Repeat("x", 5000) + keywordNumber)))

	for _, decoder := range []bool{false, true} {
		m := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, keywordMode: true}
		defer m.releaseProjection()
		m.reassemblyObserve(body + strings.Repeat("!", 20))
		kind := assembledInputView
		if decoder {
			kind = assembledDecoderView
		}
		m.reassemblyObserveView(body+"~~~", kind)
		result := finishAssembled(TextDLPResult{Clean: true}, m)
		if keywordFound(result) == decoder || HasInspectionLimit(result.Matches) {
			t.Fatalf("later source label, decoder=%v: %+v", decoder, result.Matches)
		}
	}
}
