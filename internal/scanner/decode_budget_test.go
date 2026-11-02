// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func decodeBudgetNestedText() string {
	nested := inspectionLimitAWSKey()
	for range 80 {
		nested = strings.ReplaceAll(nested, "A", `\u0041`)
		nested = strings.ReplaceAll(nested, `\`, `\u005c`)
	}
	return strings.Repeat("!", 128*1024) + nested
}

func TestDecodeBudgetRefusal(t *testing.T) {
	text := decodeBudgetNestedText()
	old := referenceDecodeEncodingsFixpoint(text, true)
	if len(old) == 0 {
		t.Fatal("fixture did not exercise the original work budget")
	}
	for _, d := range old {
		if strings.Contains(d.text, inspectionLimitAWSKey()) {
			t.Fatal("original walk reached the protected value")
		}
	}
	// The hidden value is reachable when the filler cannot spend the budget.
	small := strings.TrimLeft(text, "!")
	found := false
	for _, d := range decodeEncodingsFixpoint(small, true) {
		found = found || strings.Contains(d.text, inspectionLimitAWSKey())
	}
	if !found {
		t.Fatal("control failed to recover the protected value")
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	t.Run("text", func(t *testing.T) {
		result := sc.ScanTextForDLP(t.Context(), text)
		if result.Clean || !HasInspectionLimit(result.Matches) {
			t.Fatalf("clean=%v matches=%v", result.Clean, matchNames(result.Matches))
		}
	})
	t.Run("URL", func(t *testing.T) {
		raw := "https://api.vendor.example/" + text
		if result := sc.ScanURLCoreFloor(raw); !IsURLInspectionLimitResult(result) {
			t.Errorf("core floor: allowed=%v reason=%s", result.Allowed, result.Reason)
		}
		// Isolate the recursive budget from the configurable URL length limit.
		sc.maxURLLength = len(raw) + 1
		if result := sc.Scan(t.Context(), raw); !IsURLInspectionLimitResult(result) {
			t.Fatalf("full URL scan: allowed=%v reason=%s", result.Allowed, result.Reason)
		}
	})
	for name, ctx := range map[string]bool{"inbound API": false, "inbound context": true} {
		t.Run(name, func(t *testing.T) {
			var result TextDLPResult
			if ctx {
				result = sc.ScanTextForDLP(WithInboundDirection(t.Context()), text)
			} else {
				result = sc.ScanTextForDLPInbound(t.Context(), text)
			}
			if HasInspectionLimit(result.Matches) {
				t.Fatal("inbound budget refusal")
			}
		})
	}
}

func TestDecodeBudgetURLDirection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	text := decodeBudgetNestedText()
	raw := "https://api.vendor.example/" + text
	cfg.FetchProxy.Monitoring.MaxURLLength = len(raw) + 1
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	ctx := WithInboundDirection(t.Context())
	parsed := mustParseURL(t, raw)
	if !sc.queryLessURLScansClean(parsed, &queryLessDLPMemo{inbound: true}) {
		t.Fatal("query-less rescan changed inbound work accounting")
	}
	if sc.queryLessURLScansClean(parsed, &queryLessDLPMemo{}) {
		t.Fatal("query-less rescan missed outbound work exhaustion")
	}
	queryURL := &url.URL{Scheme: "https", Host: "api.vendor.example", RawQuery: "value=" + url.QueryEscape(text)}
	sc.scanNestedURLs = true
	if result := sc.checkNestedURLs(ctx, queryURL); !result.Allowed {
		t.Fatalf("nested URL scan changed inbound work accounting: %s", result.Reason)
	}
	if result := sc.checkNestedURLs(t.Context(), queryURL); !IsURLInspectionLimitResult(result) {
		t.Fatal("nested URL scan missed outbound work exhaustion")
	}
	if result := sc.Scan(ctx, raw); !result.Allowed {
		t.Fatalf("inbound full URL changed: %s", result.Reason)
	}
	for _, input := range []string{raw, "://%zz" + text} {
		if result := sc.ScanURLCoreFloorWithContext(ctx, input); !result.Allowed {
			t.Fatalf("inbound URL floor changed: %s", result.Reason)
		}
		if result := sc.ScanURLCoreFloor(input); !IsURLInspectionLimitResult(result) {
			t.Fatal("outbound URL lost its work-limit refusal")
		}
	}
}

func TestDecodeBudgetWalkBoundaries(t *testing.T) {
	// HTML roots have an independent candidate budget, including its admission
	// loop before any root is expanded. Plain terminal roots need no byte budget.
	roots := make([]decodedResult, maxDecodeCandidates+1)
	for i := range roots {
		roots[i] = decodedResult{string([]byte{0x80 | byte(i>>7), 0x80 | byte(i&127)}), encodingHTML}
	}
	for _, n := range []int{maxDecodeCandidates - 1, maxDecodeCandidates, maxDecodeCandidates + 1} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			out, complete := decodeEncodingsWalk(nil, roots[:n], map[string]struct{}{}, true, 0, true)
			if len(out) != min(n, maxDecodeCandidates) || complete != (n <= maxDecodeCandidates) {
				t.Fatalf("views=%d complete=%v", len(out), complete)
			}
		})
	}
	for _, size := range []int{maxDecodeTotalBytes - 2, maxDecodeTotalBytes, maxDecodeTotalBytes + 2} {
		t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			root := decodedResult{strings.Repeat("21", size/2), encodingHTML}
			_, complete := decodeEncodingsWalk(nil, []decodedResult{root}, map[string]struct{}{}, true, 0, true)
			if complete != (size <= maxDecodeTotalBytes) {
				t.Fatalf("%d recursive bytes: complete=%v", size, complete)
			}
		})
	}
	t.Run("candidate limit during expansion", func(t *testing.T) {
		expanding := append([]decodedResult(nil), roots[:maxDecodeCandidates]...)
		expanding[len(expanding)-1] = decodedResult{"616263646566", encodingHTML}
		out, complete := decodeEncodingsWalk(nil, expanding, map[string]struct{}{}, true, 0, true)
		if complete || len(out) != maxDecodeCandidates {
			t.Fatalf("views=%d complete=%v", len(out), complete)
		}
	})
	t.Run("short roots", func(t *testing.T) {
		out, complete := decodeEncodingsWalk(nil, []decodedResult{{"!", encodingHTML}}, map[string]struct{}{}, true, 4, true)
		if !complete || len(out) != 0 {
			t.Fatal("unmatchable root spent the budget")
		}
	})
	t.Run("short decoded view", func(t *testing.T) {
		out, complete := decodeEncodingsWalk([]string{"%41"}, nil, map[string]struct{}{"%41": {}}, true, 4, true)
		if !complete || len(out) != 0 {
			t.Fatal("unmatchable child spent the budget")
		}
	})
	// Repeated roots and a view equal to the root spend no admission budget.
	duplicate := decodedResult{"!!!!", encodingHTML}
	out, complete := decodeEncodingsWalk([]string{duplicate.text}, []decodedResult{duplicate, duplicate}, map[string]struct{}{duplicate.text: {}}, true, 0, true)
	if !complete || len(out) != 0 {
		t.Fatal("duplicate exhausted the budget")
	}
	// A large terminal view is scanned even when larger than the recursive
	// byte budget; one more decode layer must instead report incomplete.
	terminal := strings.Repeat("!", maxDecodeTotalBytes+1)
	one := base64.StdEncoding.EncodeToString([]byte(terminal))
	for name, text := range map[string]string{"one layer": one, "two layers": base64.StdEncoding.EncodeToString([]byte(one))} {
		t.Run(name, func(t *testing.T) {
			views, complete := decodeEncodingsFixpointMode(text, true, 0)
			if complete != (name == "one layer") || len(views) == 0 {
				t.Fatalf("views=%d complete=%v", len(views), complete)
			}
		})
	}
}

func TestDecodeBudgetInboundAccounting(t *testing.T) {
	for _, text := range []string{decodeBudgetNestedText(), strings.Repeat("!", maxDecodeTotalBytes+1), "Tom and Jerry"} {
		want := referenceDecodeEncodingsFixpoint(text, true)
		var memo decodingMemo
		memo.inbound = true
		if got := memo.decode(text, true); !reflect.DeepEqual(got, want) {
			t.Fatal("inbound memo changed views")
		}
		// Modes must not share a memo entry even when a caller reuses its memo.
		memo.inbound = false
		got := memo.decode(text, true)
		outbound, _ := decodeEncodingsFixpointMode(text, true, 0)
		if !reflect.DeepEqual(got, outbound) {
			t.Fatal("inbound cache changed outbound views")
		}
	}
}

func TestDecodeBudgetSegmentSkipKeepsRefusal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	// Two-layer base64 whose intermediate is past the recursive budget.
	// The surrounding header is not itself that encoding, so only a segment
	// walk reaches the bound. A compiled audience then drops the credential.
	terminal := strings.Repeat("!", maxDecodeTotalBytes+1)
	inner := base64.StdEncoding.EncodeToString([]byte(terminal))
	outer := base64.StdEncoding.EncodeToString([]byte(inner))
	var segment decodingMemo
	if views := segment.decode(outer, true); segment.inspectionIncomplete() == false || len(views) == 0 {
		t.Fatalf("segment fixture did not exhaust: views=%d incomplete=%v", len(views), segment.inspectionIncomplete())
	}
	token := "ghp_" + strings.Repeat("A", 36)
	value := "Bearer " + token + "/" + outer
	var whole decodingMemo
	_ = whole.decode(value, true)
	if whole.inspectionIncomplete() {
		t.Fatal("whole header exhausted; segment skip is not isolated")
	}
	result := sc.ScanTextForDLP(t.Context(), value)
	if !HasInspectionLimit(result.Matches) {
		t.Fatalf("segment walk skipped: clean=%v matches=%v", result.Clean, matchNames(result.Matches))
	}
	kept, allows := sc.FilterHeaderDLPMatches(result.Matches, "https://api.github.com/repos/example", "Authorization", value)
	if len(allows) == 0 || !HasInspectionLimit(kept) {
		t.Fatalf("audience filter removed the budget refusal: kept=%v allows=%v", matchNames(kept), allows)
	}
	inbound := sc.ScanTextForDLP(WithInboundDirection(t.Context()), value)
	if HasInspectionLimit(inbound.Matches) {
		t.Fatal("inbound segment budget refused a response")
	}
}

func TestDecodeBudgetKnownValueURL(t *testing.T) {
	known := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	nested := `\u0051` + known[1:]
	for range 80 {
		nested = strings.ReplaceAll(nested, `\`, `\u005c`)
	}
	carrier := hex.EncodeToString([]byte(strings.Repeat("!", 128*1024)+nested)) + "Z"
	if _, complete := decodeEncodingsFixpointMode(carrier, true, 0); !complete {
		t.Fatal("ordinary graph already exhausted the budget")
	}
	sc := knownSecretEncodingScanner(t, []string{known})
	parsed, err := url.Parse("https://api.vendor.example/" + carrier)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := sc.checkDLP(parsed)
	if !IsURLInspectionLimitResult(result) {
		t.Fatalf("known-value budget: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
	inbound := decodingMemo{inbound: true}
	result, _ = sc.checkDLPWithDecodes(parsed, &inbound)
	if !result.Allowed {
		t.Fatalf("inbound known-value policy changed: %s", result.Reason)
	}
}
