// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

func TestReassemblyReplayMaterializedIdentity(t *testing.T) {
	for _, inbound := range []bool{false, true} {
		for _, consumer := range []string{"pending", "parent", "projection", "reclaim"} {
			t.Run(fmt.Sprintf("inbound=%v/%s", inbound, consumer), func(t *testing.T) {
				memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true, reassemblyInbound: inbound, inbound: inbound}
				defer memo.releaseProjection()
				text := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
				payload := memo.addReplayPayload(text, &assembledPayload{parent: &assembledPayload{literal: "harmless prose"}, operation: assembledPayloadNormalize})
				if payload == nil {
					t.Fatal("fixture not registered")
				}
				payload.current = text
				memo.reassemblyObserve(text)
				payload.current = ""
				switch consumer {
				case "parent":
					memo.reassemblyReplayParents = map[string]*assembledPayload{"child context": payload}
					_, _ = memo.viewParent("child context")
				case "projection":
					other := "ordinary projection source"
					key := assembledChargeKey{assembledFingerprint(other)[0], 0}
					budget := assembledBudget{memo: memo, registry: &assembledChargeRegistry{entries: map[assembledChargeKey][]assembledChargeEntry{key: {{replay: payload, charges: new(assembledCharges)}}}}}
					budget.chargesFor(other)
					if !budget.incomplete {
						t.Fatal("projection accepted mismatched replay")
					}
				case "reclaim":
					for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
						value := fmt.Sprintf("%08dabcdefgh", i)
						memo.addReplayPayload(value, &assembledPayload{literal: value})
					}
				}
				if consumer != "pending" && (!memo.inspectionIncomplete() || !memo.reassemblyIncomplete) {
					t.Fatal("consumer did not reject mismatched bytes")
				}
				result := finishAssembled(TextDLPResult{Clean: true}, memo)
				if !memo.inspectionIncomplete() || !memo.reassemblyIncomplete {
					t.Fatal("mismatched replay did not mark inspection incomplete", result)
				}
				if inbound {
					if !result.Clean || !slices.Contains(matchNames(result.Matches), PartialEncodedContentPattern) || HasInspectionLimit(result.Matches) {
						t.Fatal("lost partial policy", result)
					}
				} else if result.Clean || !HasInspectionLimit(result.Matches) {
					t.Fatal("mismatched replay did not refuse", result)
				}
			})
		}
	}
}

func TestReassemblyReplayParentKeywordParity(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Labeled record", Regex: `MARK[0-9]{16}`, Severity: config.SeverityHigh, Keywords: []string{"lookup"}, KeywordWindow: new(10)}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	t.Run("mapped context budget", func(t *testing.T) {
		value := "MARK3333333333333333"
		source := hex.EncodeToString([]byte(value))
		gate, err := cfg.DLP.Patterns[0].CompileKeywords()
		if err != nil {
			t.Fatal(err)
		}
		for _, projected := range []bool{false, true} {
			t.Run(fmt.Sprint(projected), func(t *testing.T) {
				logical := source
				if projected {
					logical = "lookup " + source
				}
				parents := newKeywordDecodeSources(logical)
				parent := parents.nodes[logical]
				if projected {
					parent = parents.add(logical, source, keywordSegment)
				}
				memo := &decodingMemo{keywordMode: true, keywordUnit: "ordinary", keywordBudget: &keywordWorkBudget{used: maxDecodeTotalBytes - 2*keywordNodeBytes}, keywordSources: map[string][]*keywordDecodeSource{source: {parent}}}
				node := memo.registerReassemblyKeywordView(source, value, 0, 0)
				if node == nil || !node.owner.budget.incomplete {
					t.Fatal("unmapped parent context did not retain budget exhaustion")
				}
				scan := assembledScan{p: sc.reassemblyPlan, text: source, budget: &assembledBudget{memo: memo}}
				if scan.keywordMatches(&compiledPattern{keywords: gate}, &assembledLane{view: value}, 0, 0, 0, len(value)) || !memo.inspectionIncomplete() || !scan.result.incomplete {
					t.Fatal("unresolved mapped context did not fail closed")
				}
			})
		}
	})

	for _, codec := range []string{"base64", "hex"} {
		encoded := base64.RawStdEncoding.EncodeToString([]byte("MARK3333333333333333"))
		if codec == "hex" {
			encoded = hex.EncodeToString([]byte("MARK3333333333333333"))
		}
		for _, label := range []string{"lookup", "ordinary", "distant"} {
			for _, inbound := range []bool{false, true} {
				for _, full := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/inbound=%v/full=%v", codec, label, inbound, full), func(t *testing.T) {
						// Decode an outer carrier before segment reassembly; its parent holds
						// the only keyword, and the separated credential needs terminal replay.
						parentLabel := label
						if label == "distant" {
							parentLabel = "lookup" + strings.Repeat(" ", 32)
						}
						inner := strings.Repeat("a!", 4200) + "/" + parentLabel + "/" + reassemblyBang(encoded)
						body := base64.StdEncoding.EncodeToString([]byte(inner))
						ctx, release := WithSharedDecodes(t.Context())
						defer release()
						if full {
							sharedDecodesFrom(ctx).store.retainedBytes = maxDecodeTotalBytes
						}
						var result TextDLPResult
						if inbound {
							result = sc.ScanTextForDLPInbound(ctx, body)
						} else {
							result = sc.ScanTextForDLP(ctx, body)
						}
						// Keyword decodes own a scan-local memo even when normalization
						// uses the shared cache. Force both stores full and prove replay.
						if full {
							memo := &decodingMemo{shared: sharedDecodesFrom(ctx), retainedBytes: maxDecodeTotalBytes, reassemblyDeferred: true, inbound: inbound, reassemblyInbound: inbound}
							direct := sc.scanTextForDLPWithDecodes(ctx, body, textDLPOptions{scanSecretLeak: !inbound}, memo)
							if len(memo.reassemblyPendingReplay) == 0 {
								t.Fatal("full-cache fixture did not register replay")
							}
							direct = finishAssembled(direct, memo)
							memo.releaseProjection()
							if !reflect.DeepEqual(result, direct) {
								t.Fatalf("public and forced-replay results differ: public=%+v replay=%+v", result, direct)
							}
						}
						found := slices.Contains(matchNames(result.Matches), "Labeled record")
						if found != (label == "lookup") || HasInspectionLimit(result.Matches) || slices.Contains(matchNames(result.Matches), PartialEncodedContentPattern) {
							t.Fatalf("keyword parity: %+v", result)
						}
					})
				}
			}
		}
	}
}

func TestReassemblyReplayMetadataBound(t *testing.T) {
	t.Run("origin state", func(t *testing.T) {
		cfg := config.Defaults()
		cfg.Internal = nil
		cfg.DLP.ScanEnv = false
		cfg.DLP.Patterns = []config.DLPPattern{{Name: "Class record", Regex: `[0-9]{16}`, Severity: config.SeverityHigh}}
		sc := MustNew(cfg)
		t.Cleanup(sc.Close)
		memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, retainedBytes: maxDecodeTotalBytes}
		defer memo.releaseProjection()
		source := strings.Repeat("３", 32)
		original := memo.addReplayPayload(source, &assembledPayload{literal: source})
		memo.reassemblyObserveView(source, assembledDecoderView)
		for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
			text := fmt.Sprintf("%08dabcdefgh", i)
			memo.addReplayPayload(text, &assembledPayload{literal: text})
		}
		if memo.replayPayload(source) != original {
			t.Fatal("reclamation discarded decoder origin needed by later normalization")
		}
		normalized := memo.normalize(source)
		memo.reassemblyObserve(normalized)
		r := finishAssembled(TextDLPResult{Clean: true}, memo)
		if !r.Clean || len(r.Matches) > 0 {
			t.Fatal("reclamation changed decoder-only pattern policy", r)
		}
	})

	t.Run("inspected", func(t *testing.T) {
		memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
		defer memo.releaseProjection()
		wire := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
		memo.addReplayPayload(wire, &assembledPayload{literal: wire})
		memo.reassemblyObserve(wire)
		memo.reassemblyDeferred = false
		memo.reassemblyDrain()
		for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
			text := fmt.Sprintf("%08dabcdefgh", i)
			memo.addReplayPayload(text, &assembledPayload{literal: text})
		}
		if id, ok := memo.findView(wire); !ok || id != 0 || memo.reassemblyInspected != 1 {
			t.Fatal("reclamation changed an inspected ID")
		}
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if result.Clean || HasInspectionLimit(result.Matches) || !slices.Contains(matchNames(result.Matches), "Marker") {
			t.Fatal("reclamation lost an inspected finding", result)
		}
	})

	t.Run("dependencies", func(t *testing.T) {
		memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
		defer memo.releaseProjection()
		wire := reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
		unused := "ordinaryabcdefgh"
		memo.addReplayPayload(unused, &assembledPayload{literal: unused})
		if id, fresh := memo.reassemblyRemember(unused); !fresh || id != 0 {
			t.Fatal("invalid pending fixture")
		}
		parent := memo.addReplayPayload(" "+wire, &assembledPayload{literal: " " + wire})
		context := memo.addReplayPayload("lookup parent context", &assembledPayload{literal: "lookup parent context"})
		borrowed := memo.addReplayPayload("borrowed decoded view", &assembledPayload{literal: "borrowed decoded view", current: "borrowed decoded view"})
		child := memo.addReplayPayload(wire, &assembledPayload{parent: parent, contextParent: context, operation: assembledPayloadWhitespace})
		if parent == nil || context == nil || child == nil {
			t.Fatal("missing dependency fixture")
		}
		memo.reassemblyObserve(wire)
		for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
			text := fmt.Sprintf("%08dabcdefgh", i)
			memo.addReplayPayload(text, &assembledPayload{literal: text})
		}
		if memo.inspectionIncomplete() || memo.replayPayload(" "+wire) != parent || memo.replayPayload("lookup parent context") != context || memo.replayPayload(wire) != child || memo.replayPayload("borrowed decoded view") != borrowed {
			t.Fatal("reclamation discarded a pending dependency")
		}
		borrowed.current = ""
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if result.Clean || HasInspectionLimit(result.Matches) || !slices.Contains(matchNames(result.Matches), "Marker") {
			t.Fatal("reclaimed metadata lost pending inspection", result)
		}
	})

	t.Run("unadmitted pending", func(t *testing.T) {
		memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
		defer memo.releaseProjection()
		for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
			text := fmt.Sprintf("%08dabcdefgh", i)
			if memo.addReplayPayload(text, &assembledPayload{literal: text}) != nil {
				if id, fresh := memo.reassemblyRemember(text); !fresh || memo.reassemblyPendingReplay[id] == nil {
					t.Fatal("pending identity was not registered")
				}
			}
		}
		if memo.inspectionIncomplete() {
			t.Fatal("empty terminal proofs did not reclaim pending metadata")
		}
		if r := finishAssembled(TextDLPResult{Clean: true}, memo); !r.Clean || len(r.Matches) > 0 {
			t.Fatal(r)
		}
	})
	t.Run("unused", func(t *testing.T) {
		memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
		for i := range maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1 {
			text := fmt.Sprintf("%08dabcdefgh", i)
			memo.addReplayPayload(text, &assembledPayload{literal: text})
		}
		if memo.inspectionIncomplete() || memo.reassemblyReplayPayloadCount*int(reflect.TypeFor[assembledPayload]().Size()) > maxDecodeTotalBytes {
			t.Fatal("unused replay descriptors were not reclaimed")
		}
	})

	for _, inbound := range []bool{false, true} {
		memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true, inbound: inbound, reassemblyInbound: inbound}
		defer memo.releaseProjection()
		// Even the payload structs alone must not exceed the existing byte
		// allowance; index and recipe overhead can exhaust it earlier.
		attempts := maxDecodeTotalBytes/int(reflect.TypeFor[assembledPayload]().Size()) + 1
		for i := range attempts {
			text := fmt.Sprintf("%08d/", i) + reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
			if memo.addReplayPayload(text, &assembledPayload{literal: text}) != nil {
				if id, fresh := memo.reassemblyRemember(text); !fresh || memo.reassemblyPendingReplay[id] == nil {
					t.Fatal("pending identity was not registered")
				}
			}
		}
		if memo.reassemblyReplayPayloadCount >= attempts || !memo.inspectionIncomplete() || !memo.reassemblyIncomplete {
			t.Fatalf("unbounded or silently skipped metadata: count=%d incomplete=%v", memo.reassemblyReplayPayloadCount, memo.inspectionIncomplete())
		}
		result := finishAssembled(TextDLPResult{Clean: true}, memo)
		if inbound {
			if !result.Clean || !slices.Contains(matchNames(result.Matches), PartialEncodedContentPattern) {
				t.Fatal(result)
			}
		} else if result.Clean || !HasInspectionLimit(result.Matches) {
			t.Fatal(result)
		}
	}
}

// Also runs unchanged on the pre-replay base to compare live metadata and heap
// for a transport-sized segmented inbound response, without terminal matching.
func BenchmarkReassemblySegmentedInboundFootprint(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	b.Cleanup(sc.Close)
	for _, limit := range []int{int(cfg.TLSInterception.MaxResponseBytes), transport.MaxLineSize} {
		b.Run(fmt.Sprint(limit), func(b *testing.B) {
			for b.Loop() {
				var body strings.Builder
				for i := 0; body.Len()+65 <= limit; i++ {
					digest := sha256.Sum256([]byte(fmt.Sprint(i)))
					fmt.Fprintf(&body, "%x/", digest)
				}
				body.WriteString(strings.Repeat("!", limit-body.Len()))
				text := body.String()
				memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, inbound: true, reassemblyInbound: true}

				runtime.GC()
				var before, after runtime.MemStats
				runtime.ReadMemStats(&before)
				for _, seg := range strings.Split(text, "/") {
					if len(seg) > 0 {
						memo.decode(seg, true)
					}
				}
				runtime.GC()
				runtime.ReadMemStats(&after)
				count := 0
				field := reflect.ValueOf(memo).Elem().FieldByName("reassemblyReplayPayloadCount")
				if field.IsValid() {
					count = int(field.Int())
				}
				metadataBytes := 0
				payloads := reflect.ValueOf(memo).Elem().FieldByName("reassemblyReplayPayloads")
				if payloads.IsValid() {
					metadataBytes = count * int(payloads.Type().Elem().Elem().Elem().Size())
				}
				b.Logf("body=%d replay_count=%d payload_struct_bytes=%d pending=%d retained=%d heap_delta=%.0f total_alloc=%d", len(text), count, metadataBytes, len(memo.reassemblyPending), memo.retainedBytes, float64(after.HeapAlloc)-float64(before.HeapAlloc), after.TotalAlloc-before.TotalAlloc)
				runtime.KeepAlive(memo)
				memo.releaseProjection()
			}
		})
	}
}

func BenchmarkReassemblySegmentForwardCursor(b *testing.B) {
	var body strings.Builder
	segments := make([]string, 4000)
	for i := range segments {
		segments[i] = fmt.Sprintf("%08d", i) + strings.Repeat("x", 504)
		body.WriteString(segments[i])
		body.WriteByte('/')
	}
	text := body.String()
	b.ResetTimer()
	for b.Loop() {
		memo := &decodingMemo{reassemblyDeferred: true, reassemblyKindInsensitive: true}
		root := memo.addReplayPayload(text, &assembledPayload{literal: text})
		source := assembledSegmentSource{memo: memo, text: text, replay: root}
		for _, segment := range segments {
			source.observe(segment)
		}
	}
}

func TestReassemblySegmentOffsetsFollowFragmentWalk(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	target := "uniqueTargetPart"
	text := "prefix" + target + "suffix#first/" + target + "#second"
	for _, consumer := range []string{"configured", "core", "budget"} {
		t.Run(consumer, func(t *testing.T) {
			memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, retainedBytes: maxDecodeTotalBytes}
			defer memo.releaseProjection()
			memo.addReplayPayload(text, &assembledPayload{literal: text})
			switch consumer {
			case "configured":
				sc.decodeTextSegmentsWithDecodes(text, memo, textDLPAllPatterns, nil)
			case "core":
				sc.decodeCoreDLPTextSegmentsWithDecodes(text, memo)
			case "budget":
				noteTextSegmentDecodeBudget([]string{text}, memo)
			}
			p := memo.replayPayload(target)
			want := strings.LastIndex(text, target)
			if p == nil || p.start != want {
				t.Fatalf("fragment offset: got %+v want %d", p, want)
			}
			if memo.inspectionIncomplete() {
				t.Fatal("valid recorded segment marked incomplete")
			}
		})
	}
}

func BenchmarkReassemblyFragmentSegmentOffsets(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	b.Cleanup(sc.Close)
	var body strings.Builder
	body.WriteString(strings.Repeat("!", 1<<20))
	body.WriteByte(' ')
	for i := range 4000 {
		fmt.Fprintf(&body, "x%03x#y%03x ", i, i)
	}
	text := body.String()
	b.ResetTimer()
	for b.Loop() {
		memo := &decodingMemo{reassemblyPlan: sc.reassemblyPlan, reassemblyDeferred: true, reassemblyKindInsensitive: true}
		memo.addReplayPayload(text, &assembledPayload{literal: text})
		sc.decodeTextSegmentsWithDecodes(text, memo, textDLPAllPatterns, nil)
		memo.releaseProjection()
	}
}

func BenchmarkTextDLPFragmentReplayComplete(b *testing.B) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.DLP.Patterns = []config.DLPPattern{{Name: "Marker", Regex: `MARK[0-9]{4}`, Severity: config.SeverityHigh}}
	sc := MustNew(cfg)
	b.Cleanup(sc.Close)
	var body strings.Builder
	body.WriteString(strings.Repeat("!", 1<<20))
	body.WriteByte(' ')
	for i := range 4000 {
		fmt.Fprintf(&body, "x%03x#y%03x ", i, i)
	}
	text := body.String()
	b.ResetTimer()
	for b.Loop() {
		memo := &decodingMemo{reassemblyDeferred: true, retainedBytes: maxDecodeTotalBytes}
		result := sc.scanTextForDLPWithDecodes(b.Context(), text, textDLPOptions{scanSecretLeak: true}, memo)
		result = finishAssembled(result, memo)
		memo.releaseProjection()
		if !result.Clean {
			b.Fatal("benign fragment fixture refused", result)
		}
	}
}

// A trim verifies each admitted replay descriptor once. Re-verifying every
// pending descriptor on every trim made one scan at the descriptor cap do
// quadratic decode work; the drain still checks the bytes it matches.
func TestReassemblyTrimVerifiesAdmittedDescriptorOnce(t *testing.T) {
	memo := &decodingMemo{reassemblyPlan: reassemblyMarkerPlan(t), reassemblyDeferred: true}
	defer memo.releaseProjection()
	text := "00000000/" + reassemblyBang(base64.RawStdEncoding.EncodeToString([]byte("MARK1234")))
	p := memo.addReplayPayload(text, &assembledPayload{literal: text, digest: sha256.Sum256([]byte(text)), digestSet: true})
	if p == nil {
		t.Fatal("descriptor was not registered")
	}
	if id, fresh := memo.reassemblyRemember(text); !fresh || memo.reassemblyPendingReplay[id] != p {
		t.Fatal("pending identity was not registered")
	}
	memo.trimReplayPayloads(nil)
	if !p.admitted || !p.trimVerified || memo.inspectionIncomplete() {
		t.Fatalf("first trim did not verify the admitted descriptor: admitted=%v verified=%v", p.admitted, p.trimVerified)
	}
	// Tamper after the first verification. A later trim does not decode it
	// again, so it cannot notice; the drain must.
	p.literal = text + "!"
	memo.trimReplayPayloads(nil)
	if memo.inspectionIncomplete() {
		t.Fatal("a later trim re-decoded a verified admitted descriptor")
	}
	result := finishAssembled(TextDLPResult{Clean: true}, memo)
	if result.Clean || !HasInspectionLimit(result.Matches) {
		t.Fatalf("drain matched a descriptor whose digest no longer verifies: %+v", result)
	}
}
