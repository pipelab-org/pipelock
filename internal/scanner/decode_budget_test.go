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

// Keep the production bounds pinned independently of the fixture sizes.
func TestDecodeBudgetProductionDefaults(t *testing.T) {
	if maxDecodeTotalBytes != 8*1024*1024 {
		t.Fatalf("recursive decode budget = %d, want 8 MiB", maxDecodeTotalBytes)
	}
	cfg := config.Defaults()
	if cfg.RequestBodyScanning.MaxBodyBytes != 5*1024*1024 {
		t.Fatalf("default body cap = %d, want 5 MiB", cfg.RequestBodyScanning.MaxBodyBytes)
	}
	if cfg.WebSocketProxy.MaxMessageBytes != 1024*1024 {
		t.Fatalf("default frame cap = %d, want 1 MiB", cfg.WebSocketProxy.MaxMessageBytes)
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
			out, complete := decodeEncodingsWalk(nil, nil, roots[:n], newDecodeSeen(), true, 0, true)
			if len(out) != min(n, maxDecodeCandidates) || complete != (n <= maxDecodeCandidates) {
				t.Fatalf("views=%d complete=%v", len(out), complete)
			}
		})
	}
	for _, size := range []int{maxDecodeTotalBytes - 2, maxDecodeTotalBytes, maxDecodeTotalBytes + 2} {
		t.Run(fmt.Sprintf("bytes_%d", size), func(t *testing.T) {
			root := decodedResult{strings.Repeat("21", size/2), encodingHTML}
			_, complete := decodeEncodingsWalk(nil, nil, []decodedResult{root}, newDecodeSeen(), true, 0, true)
			if complete != (size <= maxDecodeTotalBytes) {
				t.Fatalf("%d recursive bytes: complete=%v", size, complete)
			}
		})
	}
	t.Run("candidate limit during expansion", func(t *testing.T) {
		expanding := append([]decodedResult(nil), roots[:maxDecodeCandidates]...)
		expanding[len(expanding)-1] = decodedResult{"616263646566", encodingHTML}
		out, complete := decodeEncodingsWalk(nil, nil, expanding, newDecodeSeen(), true, 0, true)
		if complete || len(out) != maxDecodeCandidates {
			t.Fatalf("views=%d complete=%v", len(out), complete)
		}
	})
	t.Run("short roots", func(t *testing.T) {
		out, complete := decodeEncodingsWalk(nil, nil, []decodedResult{{"!", encodingHTML}}, newDecodeSeen(), true, 4, true)
		if !complete || len(out) != 0 {
			t.Fatal("unmatchable root spent the budget")
		}
	})
	t.Run("short decoded view", func(t *testing.T) {
		out, complete := decodeEncodingsWalk(nil, []string{"%41"}, nil, newDecodeSeen("%41"), true, 4, true)
		if !complete || len(out) != 0 {
			t.Fatal("unmatchable child spent the budget")
		}
	})
	// Repeated roots and a view equal to the root spend no admission budget.
	duplicate := decodedResult{"!!!!", encodingHTML}
	out, complete := decodeEncodingsWalk(nil, []string{duplicate.text}, []decodedResult{duplicate, duplicate}, newDecodeSeen(duplicate.text), true, 0, true)
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
	t.Parallel()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	// A base64 segment reveals enough nested JSON escapes to spend the
	// recursive budget. The surrounding header isn't that encoding, so only
	// a segment walk reaches the bound. An audience then drops the credential.
	// Large first-layer and terminal views are covered by the walk boundaries.
	outer := base64.StdEncoding.EncodeToString([]byte(decodeBudgetNestedText()))
	token := "ghp_" + strings.Repeat("A", 36)
	value := "Bearer " + token + "/" + outer
	// The whole header does not exhaust, so the inspection limit asserted
	// below can only come from the segment walk.
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

// The nested-escape segment tests above spend the budget through cumulative
// expansions. This is the other bound: a segment whose first decode layer is
// past the recursive budget must be decoded once more, and that second layer
// must report incomplete. Only the decode of each segment is exercised, so the
// over-budget carrier costs a base64 decode rather than a full scan.
func TestDecodeBudgetSegmentNoteLargeIntermediate(t *testing.T) {
	t.Parallel()
	terminal := strings.Repeat("!", maxDecodeTotalBytes+1)
	one := base64.StdEncoding.EncodeToString([]byte(terminal))
	two := base64.StdEncoding.EncodeToString([]byte(one))
	token := "ghp_" + strings.Repeat("A", 36)
	for _, tc := range []struct {
		name       string
		segment    string
		inbound    bool
		incomplete bool
	}{
		{"one layer is covered by the transport limit", one, false, false},
		{"over-budget intermediate refuses", two, false, true},
		{"inbound keeps the partial-view policy", two, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			memo := decodingMemo{inbound: tc.inbound}
			noteTextSegmentDecodeBudget([]string{"Bearer " + token + "/" + tc.segment}, &memo)
			if got := memo.inspectionIncomplete(); got != tc.incomplete {
				t.Fatalf("inspectionIncomplete=%v, want %v", got, tc.incomplete)
			}
		})
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

// The segment matcher also walks the HTML-entity-decoded view. A segment that
// only becomes the over-budget encoding after entity decoding must still
// refuse when a credential stopped the matcher first.
func TestDecodeBudgetSegmentSkipCoversHTMLView(t *testing.T) {
	t.Parallel()
	for _, coreOnly := range []bool{false, true} {
		t.Run(fmt.Sprintf("core_only_%v", coreOnly), func(t *testing.T) {
			t.Parallel()
			testDecodeBudgetSegmentHTMLView(t, coreOnly)
		})
	}
}

func testDecodeBudgetSegmentHTMLView(t *testing.T, coreOnly bool) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	if coreOnly {
		cfg.DLP.Patterns = nil
		cfg.SeedPhraseDetection.Enabled = new(bool)
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	outer := base64.StdEncoding.EncodeToString([]byte(decodeBudgetNestedText()))
	entity := fmt.Sprintf("&#%d;", outer[0]) + outer[1:]
	token := "ghp_" + strings.Repeat("A", 36)
	value := "Bearer " + token + "/" + entity

	var plain decodingMemo
	for _, seg := range textDLPSegments(value) {
		if len(seg) >= 10 {
			_ = plain.decode(seg, true)
		}
	}
	if plain.inspectionIncomplete() {
		t.Fatal("plain view exhausted; the HTML view is not isolated")
	}
	result := sc.ScanTextForDLP(t.Context(), value)
	if !HasInspectionLimit(result.Matches) {
		t.Fatalf("HTML view segment walk skipped: clean=%v matches=%v", result.Clean, matchNames(result.Matches))
	}
	kept, allows := sc.FilterHeaderDLPMatches(result.Matches, "https://api.github.com/repos/example", "Authorization", value)
	if len(allows) == 0 || !HasInspectionLimit(kept) {
		t.Fatalf("audience filter removed the HTML budget refusal: kept=%v allows=%v", matchNames(kept), allows)
	}
	inbound := sc.ScanTextForDLP(WithInboundDirection(t.Context()), value)
	if HasInspectionLimit(inbound.Matches) {
		t.Fatal("inbound HTML segment budget refused a response")
	}
}

// The API-key remainder rescan keeps the outer scan's work accounting, like
// the query-less rescan beside it.
func TestDecodeBudgetAPIKeyRescanKeepsDirection(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.APIAllowlist = nil
	cfg.DLP.ScanEnv = false
	key := "AIza" + strings.Repeat("a", 35)
	raw := "https://generativelanguage.googleapis.com/v1beta/models?key=" + key + "&x=" + url.QueryEscape(decodeBudgetNestedText())
	cfg.FetchProxy.Monitoring.MaxURLLength = len(raw) + 1
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	var google *compiledPattern
	for _, p := range sc.dlpPatterns {
		if p.name == "Google API Key" {
			google = p
		}
	}
	if google == nil {
		t.Fatal("Google API Key pattern not compiled")
	}
	parsed := mustParseURL(t, raw)
	if got := sc.urlDLPAudienceSurface(google, parsed, &queryLessDLPMemo{inbound: true}); got != credentialAudienceURLQuerySurface {
		t.Fatalf("inbound remainder rescan used outbound accounting: surface=%q", got)
	}
	if got := sc.urlDLPAudienceSurface(google, parsed, &queryLessDLPMemo{}); got == credentialAudienceURLQuerySurface {
		t.Fatal("outbound remainder rescan missed work exhaustion")
	}
}

// A known value matched directly must not hide a carrier whose decoded
// known-value walk passes the work budget.
func TestDecodeBudgetKnownValueEarlyMatchKeepsRefusal(t *testing.T) {
	known := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	nested := `\u0051` + known[1:]
	for range 80 {
		nested = strings.ReplaceAll(nested, `\`, `\u005c`)
	}
	carrier := hex.EncodeToString([]byte(strings.Repeat("!", 128*1024)+nested)) + "Z"
	sc := knownSecretEncodingScanner(t, []string{known})
	parsed := mustParseURL(t, "https://api.vendor.example/"+carrier+"?v="+known)
	var ordinary decodingMemo
	ordinary.decode(carrier, true)
	if ordinary.inspectionIncomplete() {
		t.Fatal("ordinary graph exhausted the budget")
	}
	var recovery decodingMemo
	recovery.decodeKnownSecret(carrier, min(minKnownSecretSubstringLen, sc.minEnvSecretLen))
	if !recovery.inspectionIncomplete() {
		t.Fatal("known-value recovery graph did not exhaust the budget")
	}
	var knownViews decodingMemo
	sc.decodedKnownSecretViews(parsed.String(), &knownViews)
	if !knownViews.inspectionIncomplete() {
		t.Fatal("known-value URL views did not exhaust the budget")
	}
	secrets := sc.fileSecrets
	canaries := sc.canaryTokens
	sc.fileSecrets, sc.canaryTokens = nil, nil
	ordinaryResult, _ := sc.checkDLP(parsed)
	sc.fileSecrets, sc.canaryTokens = secrets, canaries
	if !ordinaryResult.Allowed {
		t.Fatalf("ordinary URL DLP did not complete cleanly: %s", ordinaryResult.Reason)
	}
	result, _ := sc.checkDLP(parsed)
	if !IsURLInspectionLimitResult(result) {
		t.Fatalf("early known-value match hid the budget refusal: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
	inbound := decodingMemo{inbound: true}
	result, _ = sc.checkDLPWithDecodes(parsed, &inbound)
	if result.Allowed || IsURLInspectionLimitResult(result) {
		t.Fatalf("inbound known-value match changed: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
}

// Canary whitespace compaction can expose work absent from the known-value views.
func TestDecodeBudgetKnownValueEarlyMatchCanaryWalk(t *testing.T) {
	known := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	sc := knownSecretEncodingScanner(t, []string{known})
	sc.canaryTokens = []compiledCanaryToken{{name: "budget-marker", normalizedLower: "budget-marker", canonicalLower: "budgetmarker"}}
	carrier := hex.EncodeToString([]byte(decodeBudgetNestedText()))
	var split strings.Builder
	for start := 0; start < len(carrier); start += 1024 {
		split.WriteString(carrier[start:min(start+1024, len(carrier))])
		split.WriteByte(' ')
	}
	parsed := &url.URL{Scheme: "https", Host: "api.vendor.example", Path: "/", RawQuery: "carrier=" + split.String() + "&v=" + known}
	var memo decodingMemo
	sc.decodedKnownSecretViews(IterativeDecode(parsed.String()), &memo)
	sc.decodedKnownSecretViews(parsed.String(), &memo)
	if memo.inspectionIncomplete() {
		t.Fatal("known-value walks already exhausted the budget")
	}
	sc.scanCanaryTextWithDecodes(parsed.String(), &memo)
	if !memo.inspectionIncomplete() {
		t.Fatal("canary walk did not exhaust the budget")
	}
	secrets := sc.fileSecrets
	canaries := sc.canaryTokens
	sc.fileSecrets, sc.canaryTokens = nil, nil
	ordinaryResult, _ := sc.checkDLP(parsed)
	sc.fileSecrets, sc.canaryTokens = secrets, canaries
	if !ordinaryResult.Allowed {
		t.Fatalf("ordinary URL DLP did not complete cleanly: %s", ordinaryResult.Reason)
	}
	result, _ := sc.checkDLP(parsed)
	if !IsURLInspectionLimitResult(result) {
		t.Fatalf("early match hid canary refusal: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
	inbound := decodingMemo{inbound: true}
	result, _ = sc.checkDLPWithDecodes(parsed, &inbound)
	if result.Allowed || IsURLInspectionLimitResult(result) {
		t.Fatalf("inbound known-value match changed: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
}

// A known value on a small outbound URL keeps its ordinary finding: the
// early-match budget check applies only when a skipped walk is exhausted.
func TestDecodeBudgetKnownValueCompleteWalkIsOrdinaryFinding(t *testing.T) {
	known := strings.Join([]string{"Q7m2", "X9z4", "R8v3", "N6p1"}, "")
	sc := knownSecretEncodingScanner(t, []string{known})
	parsed, err := url.Parse("https://api.vendor.example/upload?v=" + known)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := sc.checkDLP(parsed)
	if result.Allowed || result.Scanner != ScannerDLP || !strings.HasPrefix(result.Reason, "known secret leak detected") {
		t.Fatalf("complete-walk known value: allowed=%v reason=%s", result.Allowed, result.Reason)
	}
}
