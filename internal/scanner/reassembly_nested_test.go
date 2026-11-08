// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyNestedViews(t *testing.T) {
	key := inspectionLimitAWSKey()
	target := sha256.Sum256([]byte(key))
	inner := strings.Repeat("a!", 4200) + reassemblyBang(hex.EncodeToString([]byte(key)))
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	for _, outer := range []struct{ name, text string }{{"base64", base64.StdEncoding.EncodeToString([]byte(inner))}, {"hex", hex.EncodeToString([]byte(inner))}} {
		for _, inbound := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/inbound=%v", outer.name, inbound), func(t *testing.T) {
				ctx := t.Context()
				if inbound {
					ctx = WithInboundDirection(ctx)
				}
				r := sc.ScanTextForDLP(ctx, outer.text)
				found := slices.ContainsFunc(r.Matches, func(m TextDLPMatch) bool {
					return m.PatternName == "AWS Access ID" && m.hasValueIdentity && m.valueIdentity == target
				})
				if !found || r.Clean || r.Incomplete || HasInspectionLimit(r.Matches) {
					t.Fatal("nested credential lost", r)
				}
			})
		}
	}
	raw := dataURLForPNGBytes(t, pngWithLiteralInTextChunk(t, inner))
	for _, disabled := range []bool{false, true} {
		candidate := MustNew(cfg)
		if disabled {
			candidate.reassemblyPlan = nil
		}
		r := candidate.ScanTextForDLP(t.Context(), raw)
		candidate.Close()
		found := slices.Contains(matchNames(r.Matches), "AWS Access ID")
		if found == disabled || r.Incomplete || HasInspectionLimit(r.Matches) {
			t.Fatal("PNG control changed", disabled, r)
		}
	}
}
