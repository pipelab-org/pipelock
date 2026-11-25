// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/carddlp"
	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestCardURLDecodeAdmission(t *testing.T) {
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"", false},
		{"updated", false},
		{"v2items123updated", false},
		{strings.Repeat("A", 18), false},
		{strings.Repeat("A", 19), true},
		{"%34", true},
		{"1+2", true},
		{"&#52;", true},
		{`\u0034`, true},
		{"=34", true},
		{"４", true},
	} {
		if got := cardDecodeMayFit(tc.text, carddlp.MinDigits); got != tc.want {
			t.Errorf("admission %q = %v, want %v", tc.text, got, tc.want)
		}
	}
	// The shortest supported card still reaches the complete decoder. Compare
	// its output with an unrestricted memo, rather than a separate codec model.
	pan := "36" + strings.Repeat("1", carddlp.MinDigits-2)
	text := base64.RawStdEncoding.EncodeToString([]byte(pan))
	restricted := &decodingMemo{minimumDecodedBytes: carddlp.MinDigits}
	got := restricted.decode(text, true)
	unrestricted := (&decodingMemo{}).decode(text, true)
	if len(got) != len(unrestricted) || len(got) == 0 {
		t.Fatalf("shortest card decode lost: %v / %v", got, unrestricted)
	}
	for i := range got {
		if got[i].text != unrestricted[i].text || got[i].encoding != unrestricted[i].encoding {
			t.Fatal("restricted decode changed output", got, unrestricted)
		}
	}
}

func TestCardURLEmptyPartition(t *testing.T) {
	var sc Scanner
	memo := &decodingMemo{}
	matches := sc.textURLCardMatches(t.Context(), "https://api.vendor.example/path?first=ordinary&second=notes", memo)
	if len(matches) != 0 || len(memo.views) != 0 {
		t.Fatalf("disabled card partition performed URL work: matches=%v decoded roots=%d", matches, len(memo.views))
	}
}

func TestCardURLTerminalFollowsMain(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	for _, tc := range []struct {
		name    string
		inbound bool
	}{{"outbound", false}, {"inbound", true}} {
		t.Run(tc.name, func(t *testing.T) {
			allowance := &assembledAllowance{}
			memo := textDecodingMemo(nil, tc.inbound, allowance, false)
			defer memo.releaseTextDecodingMemo()
			memo.reassemblyPlan = sc.reassemblyPlan
			memo.cardSource = true
			memo.inbound = tc.inbound
			memo.scanCtx = t.Context()
			memo.scanStop = true
			pan := cardtest.Issuer("4019", 16)
			wire := "https://api.vendor.example/?value=" + reassemblyBang(hex.EncodeToString([]byte(pan)))
			matches := sc.textURLCardMatches(t.Context(), wire, memo)
			if allowance.used != 0 {
				t.Fatalf("URL-only terminal consumed %d bytes before the main terminal", allowance.used)
			}
			if memo.urlCardDecodes == nil || !memo.urlCardDecodes.inbound || memo.urlCardDecodes.reassemblyInbound != tc.inbound {
				t.Fatal("URL card decoder or terminal changed its directional policy")
			}
			result := finishAssembled(TextDLPResult{Matches: matches}, memo)
			if allowance.used == 0 || !HasEnforcingMatch(result.Matches) {
				t.Fatalf("deferred URL work was lost: used=%d result=%+v", allowance.used, result)
			}
		})
	}
}
