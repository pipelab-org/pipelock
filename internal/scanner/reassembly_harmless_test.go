// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestReassemblyHarmlessTraffic(t *testing.T) {
	cases := []struct{ name, text string }{
		{"prose", strings.Repeat("The service returns ordinary status updates for the current request. ", 80)},
		{"hashes", strings.Repeat("artifact: "+strings.Repeat("3", 64)+"\n", 80)},
		{"identifiers", strings.Repeat("123e4567-e89b-12d3-a456-000000000001\n", 100)},
		{"javascript", strings.Repeat("function f(a,b){return a.b+c(a,b);}", 100)},
		{"diff", strings.Repeat("diff --git a/file.txt b/file.txt\n@@ -1,2 +1,2 @@\n-ordinary line\n+ordinary line changed\n", 40)},
		{"zero hex", strings.Repeat("00 ", 8192)},
		{"space hex", strings.Repeat("20 ", 8192)},
		{"benign encoded", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("ordinary status line for the attachment.\n", 400)))},
	}
	for _, seed := range []int64{1, 2, 3, 4} {
		rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- reproducible binary response corpus.
		data := make([]byte, maxReassembledTokenLen)
		if _, err := rng.Read(data); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct{ name, text string }{fmt.Sprintf("binary-base64-%d", seed), base64.StdEncoding.EncodeToString(data)})
		cases = append(cases, struct{ name, text string }{fmt.Sprintf("binary-hex-%d", seed), hex.EncodeToString(data)})
	}
	for _, expr := range admissionProbePatterns {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{Name: "Configured record", Regex: expr, Severity: config.SeverityHigh})
		sc := MustNew(cfg)
		t.Cleanup(sc.Close)
		for _, tc := range cases {
			for _, inbound := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/inbound=%v", expr, tc.name, inbound), func(t *testing.T) {
					t.Parallel()
					ctx := t.Context()
					if inbound {
						ctx = WithInboundDirection(ctx)
					}
					result := sc.ScanTextForDLP(ctx, tc.text)
					if HasInspectionLimit(result.Matches) || result.Incomplete {
						t.Fatal("harmless content refused", result)
					}
				})
			}
		}
	}
}

func TestReassemblyRandomBinaryResponse(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	defer sc.Close()
	for _, seed := range []int64{1, 2, 3, 4} {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- reproducible binary response corpus.
			data := make([]byte, 64<<10)
			if _, err := rng.Read(data); err != nil {
				t.Fatal(err)
			}
			encoded := base64.StdEncoding.EncodeToString(data)
			response := sc.ScanResponse(t.Context(), encoded)
			if response.ScanError != "" {
				t.Fatal("binary response inspection failed", response.ScanError)
			}
			result := sc.ScanTextForDLPInbound(t.Context(), encoded)
			if result.Incomplete || HasInspectionLimit(result.Matches) {
				t.Fatal("inbound binary response refused", result)
			}
		})
	}
}

// Image and document uploads carry bare base64 that the data-URL excision
// does not remove. Short cues must not admit enough whole decoded lanes in
// that junk to exhaust the terminal allowance and refuse the upload.
func TestReassemblyLargeBinaryUploadAdmission(t *testing.T) {
	p := reassemblyTestPlan(t)
	for _, size := range []int{3 << 19, 3 << 20} {
		for _, seed := range []int64{1, 2, 3} {
			t.Run(fmt.Sprintf("%d/%d", size, seed), func(t *testing.T) {
				t.Parallel()
				rng := rand.New(rand.NewSource(seed)) // #nosec G404 -- reproducible binary upload corpus.
				data := make([]byte, size)
				if _, err := rng.Read(data); err != nil {
					t.Fatal(err)
				}
				text := `{"messages":[{"role":"user","content":[{"type":"image","source":{"type":"base64","media_type":"image/png","data":"` +
					base64.StdEncoding.EncodeToString(data) + `"}},{"type":"text","text":"Describe this image."}]}]}`
				budget := &assembledBudget{}
				if r := reassemblyTerminal(p, text, budget); r.incomplete {
					t.Fatalf("harmless upload exhausted the decoded allowance after %d bytes", budget.used)
				}
			})
		}
	}
}

// A finite shape's class run is only a necessary condition. A run that no
// grammar alignment can match must not decode a whole lane per codec, phase
// and view; random image bytes contain such runs.
func TestReassemblyShapeRunOutsideGrammar(t *testing.T) {
	p := reassemblyTestPlan(t)
	junk := strings.Repeat("\xc3\x97\xe2\x80\xa2", 40)
	for _, enc := range reassemblyEncodings(junk + "JTz4CS0CHadTbFu" + junk) {
		budget := &assembledBudget{}
		r := assembledLayer(p, enc.text, budget, 0)
		if len(r.findings) > 0 || r.incomplete || budget.used != 0 {
			t.Errorf("%s: findings=%d incomplete=%v decoded=%d", enc.name, len(r.findings), r.incomplete, budget.used)
		}
	}
	for _, enc := range reassemblyEncodings(junk + "GB82" + "WEST12345698765432" + junk) {
		if r := reassemblyTerminal(p, enc.text, &assembledBudget{}); len(r.findings) == 0 {
			t.Errorf("%s: IBAN beside the same junk was not detected", enc.name)
		}
	}
}

// The dotted Discord cue checks its middle segment. The shipped grammar also
// needs 23 class runes before the first dot; random bytes rarely supply them.
func TestReassemblyDottedCueNeedsLeadingRun(t *testing.T) {
	p := reassemblyTestPlan(t)
	junk := strings.Repeat("\xc3\x97\xe2\x80\xa2", 40)
	head, tail := "q7Hw2Lm9Zx4Rt6Yp1Vb8Nc", "Kd3Fg5Jh7Ws9Ea2Qr4Ty6Ui8Op1"
	for _, enc := range reassemblyEncodings(junk + "\x01" + head + ".abcdef." + tail + junk) {
		budget := &assembledBudget{}
		r := assembledLayer(p, enc.text, budget, 0)
		if len(r.findings) > 0 || r.incomplete || budget.used != 0 {
			t.Errorf("%s: findings=%d incomplete=%v decoded=%d", enc.name, len(r.findings), r.incomplete, budget.used)
		}
	}
	for _, plain := range []string{
		junk + "Nj" + head + ".abcdef." + tail + junk,
		junk + "M" + strings.Repeat("K", 23) + "." + strings.Repeat("ſ", 6) + "." + strings.Repeat("c", 27) + junk,
	} {
		for _, enc := range reassemblyEncodings(plain) {
			if r := assembledLayer(p, enc.text, &assembledBudget{}, 0); len(r.findings) == 0 {
				t.Errorf("%s: dotted token beside the same junk was not detected", enc.name)
			}
		}
	}
}
