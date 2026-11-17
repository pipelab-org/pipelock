// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"html"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDetectorCacheLifetime(t *testing.T) {
	var absent *decodingMemo
	absent.releaseDetectorCache()
	var memo decodingMemo
	const carrier = "aGVsbG8="
	views := memo.decode(carrier, true)
	memo.normalize("ordinary text")
	memo.retainDecodedMatches(decodedMatchKey{text: "candidate", encoding: encodingBase64}, make([]TextDLPMatch, 0, 2))
	memo.compactWhitespace("one two")
	if len(views) == 0 || len(memo.decodedMatches) == 0 || !memo.compactReady || len(memo.compactOffsets) == 0 {
		t.Fatal("fixture did not populate each cache")
	}
	viewCount, normalizedCount := len(memo.views), len(memo.normalized)
	released := memo.decodedMatchesBytes + cap(memo.compactOffsets)*(strconv.IntSize/8)
	if !memo.reservePayloadBytes(maxDecodeTotalBytes-memo.retainedBytes) || memo.reservePayloadBytes(1) {
		t.Fatal("fixture did not exhaust the existing retention allowance")
	}
	memo.incomplete = true
	memo.releaseDetectorCache()
	if len(memo.decodedMatches) != 0 || memo.decodedMatchesBytes != 0 || memo.compactReady || memo.compactOffsets != nil || memo.compactSource != "" || memo.compactText != "" {
		t.Fatal("finished detector caches are still retained")
	}
	if !memo.incomplete || len(memo.views) != viewCount || len(memo.normalized) != normalizedCount {
		t.Fatal("cache release changed inspection state or decoded views")
	}
	if memo.retainedBytes != maxDecodeTotalBytes-released {
		t.Fatalf("retained bytes %d, want %d", memo.retainedBytes, maxDecodeTotalBytes-released)
	}
	memo.releaseDetectorCache()
	if !memo.reservePayloadBytes(released) || memo.reservePayloadBytes(1) {
		t.Fatal("released bytes were not reusable exactly once within the existing allowance")
	}
	if got := memo.decode(carrier, true); len(got) != len(views) || &got[0] != &views[0] {
		t.Fatal("decoded graph was evicted with the finished pattern cache")
	}
}

func TestDetectorCacheLifetimeKeepsSharedOwners(t *testing.T) {
	shared := &sharedDecodes{}
	shared.store.retainDecodedMatches(decodedMatchKey{text: "other scan", encoding: encodingHex}, nil)
	memo := &decodingMemo{shared: shared}
	memo.compactWhitespace("one two")
	charged := shared.store.retainedBytes
	if charged == 0 || !memo.compactReady {
		t.Fatal("fixture did not retain shared scan state")
	}
	memo.releaseDetectorCache()
	if shared.store.retainedBytes != charged || len(shared.store.decodedMatches) != 1 || !memo.compactReady {
		t.Fatal("local phase release changed a shared owner's state")
	}
}

func TestScanTextDLPCancellationStopsLaterPattern(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "Kept", Regex: `KEPT[0-9]{4}`, Severity: config.SeverityHigh},
		{Name: "Early", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh},
		{Name: "Late", Regex: `LATE[0-9]{4}`, Severity: config.SeverityHigh},
	}
	sc := MustNew(cfg)
	defer sc.Close()
	body := "KEPT1234 MARK1234 " + strings.Repeat("neutral status text ", 40) + "LATE5678"
	live := sc.ScanTextForDLP(t.Context(), body)
	if live.Incomplete || !hasPattern(live, "Early") || !hasPattern(live, "Late") {
		t.Fatalf("complete scan missed a marker: %+v", live)
	}

	for _, tc := range []struct {
		name   string
		scan   func(context.Context, string) TextDLPResult
		shared bool
	}{
		{name: "outbound", scan: sc.ScanTextForDLP},
		{name: "inbound", scan: sc.ScanTextForDLPInbound},
		{name: "shared", scan: sc.ScanTextForDLP, shared: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			scanCtx := ctx
			release := func() {}
			if tc.shared {
				scanCtx, release = WithSharedDecodes(ctx)
			}
			lateCalls := 0
			for i := range sc.dlpPatterns {
				pattern := sc.dlpPatterns[i]
				switch pattern.name {
				case "Early":
					pattern.validate = func(string) bool {
						cancel()
						return false
					}
				case "Late":
					pattern.validate = func(string) bool {
						lateCalls++
						return false
					}
				}
			}
			t.Cleanup(func() {
				for i := range sc.dlpPatterns {
					sc.dlpPatterns[i].validate = nil
				}
			})
			result := tc.scan(scanCtx, body)
			release()
			if ctx.Err() == nil {
				t.Fatal("early validator was not reached")
			}
			if lateCalls != 0 {
				t.Fatalf("later pattern ran after cancel: %d", lateCalls)
			}
			if !result.Incomplete || result.Clean {
				t.Fatalf("cancellation returned verified: %+v", result)
			}
			if !hasPattern(result, "Kept") {
				t.Fatalf("finding collected before cancellation was lost: %+v", result)
			}
			for _, match := range append(result.Matches, result.InformationalMatches...) {
				if match.PatternName == PartialEncodedContentPattern || match.PatternName == UninspectableEncodedContentPattern {
					t.Fatalf("cancellation became an inspection-limit finding: %+v", result)
				}
			}
		})
	}

	again := sc.ScanTextForDLP(t.Context(), body)
	if again.Incomplete || !hasPattern(again, "Early") || !hasPattern(again, "Late") {
		t.Fatalf("canceled scan cached as a verified negative: %+v", again)
	}
}

func TestScanTextDLPCancellationSurvivesCardPass(t *testing.T) {
	for _, separate := range []bool{false, true} {
		t.Run(strconv.FormatBool(separate), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.DLP.ScanEnv = false
			cfg.DLP.Patterns = append(cfg.DLP.Patterns,
				config.DLPPattern{Name: "Cancel first pass", Regex: `MARK[0-9]{4}`, Keywords: []string{"lookup"}, Severity: config.SeverityHigh},
				config.DLPPattern{Name: "Card counter", Regex: `4111[0-9]{12}`, Validator: config.ValidatorLuhn, Severity: config.SeverityHigh},
			)
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var cardCalls, callsAtCancel int
			var canceled bool
			for _, patterns := range [][]*compiledPattern{sc.core.dlpPatterns, sc.dlpPatterns} {
				for _, p := range patterns {
					if p.genericCard {
						p.validateAt = func(string, int, int) bool { cardCalls++; return true }
					}
					if p.name == "Cancel first pass" {
						p.validate = func(string) bool {
							if !canceled {
								callsAtCancel = cardCalls
								canceled = true
								cancel()
							}
							return true
						}
					}
				}
			}
			text := "lookup MARK1234 4111" + strings.Repeat("1", 12)
			cardView := text
			if separate {
				cardView += " separate view"
			}
			result := sc.ScanTextForDLPWithCardView(ctx, text, cardView)
			if ctx.Err() == nil || !result.Incomplete || result.Clean {
				t.Fatalf("fixture did not stop during the first pass: %+v", result)
			}
			if cardCalls != callsAtCancel {
				t.Fatalf("card work resumed after cancellation: calls=%d atCancel=%d", cardCalls, callsAtCancel)
			}
		})
	}
}

type cancelAfterBaseDecodeContext struct {
	context.Context
	memo   *decodingMemo
	cancel context.CancelFunc
}

func (c *cancelAfterBaseDecodeContext) Done() <-chan struct{} {
	if len(c.memo.views) > 0 {
		c.cancel()
	}
	return c.Context.Done()
}

func TestKnownSecretCancellationBetweenDecodeWalks(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	sc.minEnvSecretLen = minKnownSecretSubstringLen
	parent, cancel := context.WithCancel(t.Context())
	defer cancel()
	memo := &decodingMemo{scanStop: true}
	memo.scanCtx = &cancelAfterBaseDecodeContext{Context: parent, memo: memo, cancel: cancel}
	text := base64.RawStdEncoding.EncodeToString([]byte("ordinary decoded marker for cancellation"))
	views := sc.decodedKnownSecretViews(text, memo)
	if parent.Err() == nil || len(views) == 0 {
		t.Fatalf("base result was not preserved at cancellation: views=%d error=%v", len(views), parent.Err())
	}
	for key := range memo.views {
		if key.minPrefix > 0 {
			t.Fatal("known-prefix walk started after the completed base walk canceled")
		}
	}
}

func TestSecretLeakCancellationKeepsEarlierFinding(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	const value = "known-cancellation-marker-abcdefgh"
	sc.envSecrets = []string{value}
	control := newDoneCounter(t, 0)
	first := sc.checkSecretLeaks(value, value, &decodingMemo{scanCtx: control, scanStop: true})
	if len(first) != 1 || control.hits == 0 {
		t.Fatal("control did not finish the environment finding")
	}
	// The environment-only control's final checkpoint is the next independent
	// check's entry when a file secret is configured. Derive that boundary
	// from the control rather than relying on a fixed checkpoint count.
	sc.fileSecrets = []string{value}
	ctx := newDoneCounter(t, control.hits)
	found := sc.checkSecretLeaks(value, value, &decodingMemo{scanCtx: ctx, scanStop: true})
	if ctx.Err() == nil || len(found) != 1 || found[0].PatternName != "Environment Variable Leak" {
		t.Fatalf("independent check resumed or earlier finding was lost: findings=%+v error=%v", found, ctx.Err())
	}
}

func TestScanTextDLPPrecancelKeepsFindings(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{
		{Name: "Anchored", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh},
		{Name: "Class", Regex: `[A-Z]{6}[0-9]{4}`, Severity: config.SeverityHigh},
	}
	sc := MustNew(cfg)
	defer sc.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	body := "MARK1234 ABCDEF5678 " + strings.Repeat("neutral ", 100)
	result := sc.ScanTextForDLP(ctx, body)
	if !result.Incomplete || result.Clean {
		t.Fatalf("precancel returned verified: %+v", result)
	}
	if !hasPattern(result, "Anchored") || !hasPattern(result, "Class") {
		t.Fatalf("precancel dropped findings: %+v", result)
	}
	for _, match := range append(result.Matches, result.InformationalMatches...) {
		if match.PatternName == PartialEncodedContentPattern || match.PatternName == UninspectableEncodedContentPattern {
			t.Fatalf("precancel became an inspection-limit finding: %+v", result)
		}
	}
	live := sc.ScanTextForDLP(t.Context(), body)
	if live.Incomplete || !hasPattern(live, "Anchored") || !hasPattern(live, "Class") {
		t.Fatalf("precancel poisoned the next scan: %+v", live)
	}
}

func TestDecodeHTMLEntitiesUnchangedAmpersand(t *testing.T) {
	cases := []string{
		"plain",
		"a&b",
		"a&b ",
		"&",
		"&amp;",
		"&lt;tag&gt;",
		"&#65;",
		"&#x41;",
		"&amp;lt;",
		"&#;",
		"already done",
	}
	for _, text := range cases {
		got, ok := decodeHTMLEntitiesChecked(text)
		want := html.UnescapeString(text)
		// Nested passes keep decoding while the bounded loop still changes.
		for range maxHTMLEntityDecodePasses - 1 {
			next := html.UnescapeString(want)
			if next == want {
				break
			}
			want = next
		}
		if !ok && html.UnescapeString(got) != got {
			t.Fatalf("%q did not converge: %q", text, got)
		}
		if got != want {
			t.Fatalf("%q got %q want %q", text, got, want)
		}
	}
	text := strings.Repeat("a&b ", 20000)
	allocs := testing.AllocsPerRun(20, func() {
		got, ok := decodeHTMLEntitiesChecked(text)
		if !ok || got != text {
			t.Fatalf("unchanged text got %q ok %v", got, ok)
		}
	})
	if allocs != 0 {
		t.Fatalf("unchanged ampersands allocated %v times", allocs)
	}
}

func TestHTMLEntityAdmissionMatchesUnescape(t *testing.T) {
	// The standard library owns the accepted references, including omitted
	// semicolons, partial named matches and malformed numeric references.
	for _, entity := range []string{
		"&", "&&", "&a", "&aa", "&amp", "&amp;", "&ampx", "&AMP;", "&notit;", "&notin;", "&notinE;", "&acE;", "&CounterClockwiseContourIntegral;",
		"&#", "&#;", "&#x", "&#X", "&#x;", "&#0", "&#128;", "&#xD800;", "&#1114112;", "&#9999999999999999999999999;", "&#-1;", "&é;",
	} {
		for _, tail := range []string{"", ";", "=x", "&amp;", "\x00", " ordinary text"} {
			text := "prefix " + entity + tail
			want := html.UnescapeString(text) != text
			if got := htmlEntityChanges(text); got != want {
				t.Errorf("%q: admission=%v unescape changes=%v", text, got, want)
			}
		}
	}
}

func TestSum256StringMatchesSum(t *testing.T) {
	samples := []string{"", "a", strings.Repeat("digest ", 20), strings.Repeat("雪", 40)}
	for _, sample := range samples {
		if sum256String(sample) != sha256.Sum256([]byte(sample)) {
			t.Fatalf("digest mismatch len %d", len(sample))
		}
	}
	text := strings.Repeat("replay-bytes ", 500)
	memo := &decodingMemo{}
	payload := memo.addReplayPayload(text, &assembledPayload{literal: text})
	if payload == nil {
		t.Fatal("payload was not registered")
	}
	if memo.replayPayload(text) != payload {
		t.Fatal("replay missed the registered payload")
	}
	if memo.replayPayload(text+"x") != nil {
		t.Fatal("replay returned a different text")
	}
	warm := strings.Repeat("warm ", 64)
	_ = sum256String(warm)
	_ = memo.replayPayload(text)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const calls = 50
	for range calls {
		if memo.replayPayload(text) != payload {
			t.Fatal("replay missed")
		}
	}
	runtime.ReadMemStats(&after)
	perCall := uint64(0)
	if after.TotalAlloc >= before.TotalAlloc {
		perCall = (after.TotalAlloc - before.TotalAlloc) / calls
	}
	if perCall > 256 {
		t.Fatalf("replay lookup allocated %d bytes/call for %d bytes of text", perCall, len(text))
	}
}

func TestSum256StringConcurrentBuffers(t *testing.T) {
	t.Parallel()
	var workers sync.WaitGroup
	for _, size := range []int{0, 1, sha256.BlockSize - 1, sha256.BlockSize, sha256.BlockSize + 1, 4096, 10001} {
		text := strings.Repeat("x", size) + "雪" + string([]byte{0, 255})
		want := sha256.Sum256([]byte(text))
		workers.Go(func() {
			for range 20 {
				if got := sum256String(text); got != want {
					t.Errorf("shared buffer changed digest for %d input bytes", len(text))
				}
			}
		})
	}
	workers.Wait()
}

func TestIntegerByteCodeMatchesParseUint(t *testing.T) {
	samples := []string{"", "+1", "-1", " 1", "1 ", "0x10", "1_0", "1.0", "1e2", "雪", string([]byte{255}), strings.Repeat("0", 10000) + "255", strings.Repeat("9", 10000)}
	for n := range 1024 {
		samples = append(samples, strconv.Itoa(n), "000"+strconv.Itoa(n))
	}
	for _, sample := range samples {
		got, ok := integerByteCode(sample)
		want, err := strconv.ParseUint(sample, 10, 8)
		if ok != (err == nil) || ok && uint64(got) != want {
			t.Fatalf("%d-byte input: got %d/%v, want %d/%v", len(sample), got, ok, want, err)
		}
	}
	rejected := strings.Repeat("9", 10000)
	if allocs := testing.AllocsPerRun(10, func() {
		if _, ok := integerByteCode(rejected); ok {
			t.Fatal("out-of-range byte accepted")
		}
	}); allocs != 0 {
		t.Fatalf("rejected byte allocated %v objects", allocs)
	}
}
