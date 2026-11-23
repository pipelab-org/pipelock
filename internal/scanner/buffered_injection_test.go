// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func bufferedTestSurfaces() []string {
	return []string{
		config.InjectionSurfaceHTTPResponse, config.InjectionSurfaceBrowserShield, config.InjectionSurfaceHTTPRequestBody,
		config.InjectionSurfaceMCPToolInput, config.InjectionSurfaceScanAPI, config.InjectionSurfaceHookToolInput, config.InjectionSurfaceHookToolResult,
	}
}

func TestBufferedInjectionSelection(t *testing.T) {
	for _, surface := range bufferedTestSurfaces() {
		for _, mode := range []string{"legacy", config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
			t.Run(surface+"/"+mode, func(t *testing.T) {
				cfg := testResponseConfig()
				if mode != "legacy" {
					cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Surfaces: map[string]config.InjectionSurfaceConfig{surface: {Checker: config.InjectionCheckerBasic, Mode: mode}}}
				}
				sc := MustNew(cfg)
				t.Cleanup(sc.Close)
				for _, outbound := range []bool{false, true} {
					opts := BufferedInjectionScan{Surface: surface, Transport: "test", Content: checkertest.Directive, Outbound: outbound}
					got := sc.ScanBufferedInjection(t.Context(), opts)
					if got.Clean != (mode == config.InjectionModeOff || mode == config.InjectionModeWarn) {
						t.Fatalf("mode=%s clean=%v result=%+v", mode, got.Clean, got)
					}
					if mode == "legacy" {
						want := sc.ScanResponse(t.Context(), checkertest.Directive)
						if outbound {
							want = sc.ScanResponseOutbound(t.Context(), checkertest.Directive)
						}
						if !reflect.DeepEqual(got, want) {
							t.Fatalf("legacy changed: got %+v want %+v", got, want)
						}
					}
				}
			})
		}
	}
}

func TestBufferedInjectionExternal(t *testing.T) {
	for _, surface := range bufferedTestSurfaces() {
		for _, mode := range []string{config.InjectionModeOff, config.InjectionModeWarn, config.InjectionModeBlock} {
			for _, state := range []string{"benign", "finding", "not_checked", "incomplete", "failure"} {
				t.Run(surface+"/"+mode+"/"+state, func(t *testing.T) {
					srv := checkertest.New(t, state)
					cfg := testResponseConfig()
					srv.Configure(cfg, surface, mode)
					sc := MustNew(cfg)
					t.Cleanup(sc.Close)
					var events []InjectionCheckerEvent
					sc.SetInjectionCheckerHook(func(_ context.Context, e InjectionCheckerEvent) { events = append(events, e) })
					got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, Transport: "test", Content: checkertest.Directive})
					block := mode == config.InjectionModeBlock && state != "benign"
					if got.Clean == block {
						t.Fatalf("clean=%v want blocked=%v: %+v", got.Clean, block, got)
					}
					if got.Failed() != (block && state != "finding") {
						t.Fatalf("failure misclassified: %+v", got)
					}
					if got.CheckerBlocked() != (block && state == "finding") {
						t.Fatalf("finding misclassified: %+v", got)
					}
					if got.EnforcementAction(config.ActionWarn) == config.ActionBlock != (block && state == "finding") {
						t.Fatal("checker block was lowered")
					}
					if mode == config.InjectionModeOff {
						if len(srv.Items()) != 0 || got.Assessment.Status == AssessmentBenign {
							t.Fatal("off assessed content")
						}
						return
					}
					if len(srv.Items()) != 1 {
						t.Fatalf("calls=%d", len(srv.Items()))
					}
					item := srv.Items()[0]
					if item.Surface != surface || item.Transport != "test" || item.Parts[0].Text != checkertest.Directive {
						t.Fatalf("wrong item: %+v", item)
					}
					if (got.RecoveryAssessment().Status == AssessmentBenign) != (state == "benign") {
						t.Fatalf("false benign credit: %+v", got.Assessment)
					}
					expected := map[string]AssessmentStatus{"benign": AssessmentBenign, "finding": AssessmentFinding, "not_checked": AssessmentNotAssessed, "incomplete": AssessmentIncomplete, "failure": AssessmentNotAssessed}
					if got.Assessment.Status != expected[state] {
						t.Fatalf("assessment=%+v state=%s", got.Assessment, state)
					}
					if state != "benign" && len(events) != 1 {
						t.Fatalf("missing outcome: %+v", events)
					}
					for _, m := range got.Matches {
						if !strings.HasPrefix(m.PatternName, CheckerPatternPrefix) {
							t.Fatalf("basic fallback: %+v", got)
						}
					}
				})
			}
		}
	}
}

func TestBufferedInjectionViewsAndHooks(t *testing.T) {
	srv := checkertest.New(t, "finding")
	cfg := testResponseConfig()
	srv.Configure(cfg, config.InjectionSurfaceHookToolResult, config.InjectionModeBlock)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	if !sc.ScanHookInjection(t.Context(), "ordinary result", "hermes", true).CheckerBlocked() {
		t.Fatal("result helper did not route")
	}
	if !sc.ScanHookInjection(t.Context(), "ordinary input", "hermes", false).Clean {
		t.Fatal("result binding affected input")
	}
	if len(InjectionTextParts("", "hello", "ｈｅｌｌｏ")) != 3 {
		t.Fatal("original and normalized view missing")
	}
	got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: config.InjectionSurfaceHookToolResult, UseBody: true, Body: []byte("ordinary result")})
	if !got.CheckerBlocked() {
		t.Fatal("body did not route")
	}
}

func TestBufferedInjectionReloadAndWatch(t *testing.T) {
	for _, surface := range bufferedTestSurfaces() {
		t.Run(surface, func(t *testing.T) {
			srv := checkertest.New(t, "finding")
			cfg := testResponseConfig()
			srv.Configure(cfg, surface, config.InjectionModeBlock)
			old := MustNew(cfg)
			t.Cleanup(old.Close)
			for _, mode := range []string{config.InjectionModeBlock, config.InjectionModeWarn, config.InjectionModeOff} {
				next := cfg.Clone()
				next.PromptInjectionDetection.Surfaces[surface] = config.InjectionSurfaceConfig{Checker: "fixture", Mode: mode}
				sc := MustNew(next)
				t.Cleanup(sc.Close)
				r := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, Content: "ordinary text"})
				if r.CheckerBlocked() != (mode == config.InjectionModeBlock) {
					t.Fatalf("reload mode=%s: %+v", mode, r)
				}
				if !old.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, Content: "ordinary text"}).CheckerBlocked() {
					t.Fatal("old snapshot changed")
				}
			}
			watched := cfg.Clone()
			watched.PromptInjectionDetection.Surfaces[surface] = config.InjectionSurfaceConfig{Checker: config.InjectionCheckerBasic, Mode: config.InjectionModeOff, Watch: "fixture"}
			sc := MustNew(watched)
			t.Cleanup(sc.Close)
			ch := make(chan InjectionCheckerEvent, 1)
			sc.SetInjectionCheckerHook(func(_ context.Context, e InjectionCheckerEvent) { ch <- e })
			got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, Content: "ordinary text"})
			if !got.Clean || got.Assessment.Status == AssessmentBenign {
				t.Fatalf("watch changed delivery or credit: %+v", got)
			}
			select {
			case e := <-ch:
				if !e.Watch || e.Surface != surface {
					t.Fatalf("bad watch event: %+v", e)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("watch did not complete")
			}
		})
	}
}

func TestBufferedInjectionCompositionEdges(t *testing.T) {
	srv := checkertest.New(t, "benign")
	cfg := testResponseConfig()
	surface := config.InjectionSurfaceScanAPI
	srv.Configure(cfg, surface, config.InjectionModeBlock)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	var nilCtx context.Context
	if got := sc.ScanBufferedInjection(nilCtx, BufferedInjectionScan{Surface: surface}); got.Assessment.Status == AssessmentBenign {
		t.Fatal("empty content earned credit")
	}
	failure := ResponseScanResult{ScanError: "existing failure"}
	if got := sc.ComposeBufferedInjection(nilCtx, BufferedInjectionScan{Surface: surface, Content: "text"}, failure); !reflect.DeepEqual(got, failure) {
		t.Fatal("existing failure replaced")
	}
	if got := sc.ComposeBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, Content: "text", Texts: []string{""}}, ResponseScanResult{Clean: true}); got.Assessment.Status == AssessmentBenign {
		t.Fatal("empty extracted parts earned credit")
	}
	parts := InjectionTextParts("\U000E0068\U000E0069", "ｈｅｌｌｏ")
	if len(parts) < 4 {
		t.Fatalf("Unicode views absent: %+v", parts)
	}
}

func TestBufferedInjectionHookWarnRecord(t *testing.T) {
	srv := checkertest.New(t, "not_checked")
	cfg := testResponseConfig()
	srv.Configure(cfg, config.InjectionSurfaceHookToolInput, config.InjectionModeWarn)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	var warnings []string
	sc.SetInjectionWarnHook(func(_ context.Context, names []string) { warnings = append(warnings, names...) })
	got := sc.ScanHookInjection(t.Context(), "ordinary hook input", "hermes", false)
	if !got.Clean || got.Assessment.Status != AssessmentNotAssessed || len(warnings) != 1 {
		t.Fatalf("warn was silent or changed delivery: result=%+v warnings=%v", got, warnings)
	}
}

func TestBufferedInjectionBodyTextBoundary(t *testing.T) {
	for _, tc := range []struct {
		name   string
		body   []byte
		assess bool
		text   string
	}{
		{"pixels", pngWithIsolatedDANPixels(t), false, ""},
		{"metadata", pngWithMetadata(t, "tEXt", []byte("Comment\x00ordinary metadata")), true, "ordinary metadata"},
		{"wide", encodeUTF16ResponseBody("ordinary wide text", true, true), true, "ordinary wide text"},
		{"opaque", []byte{0xff, 0x00, 0xfe, 0x01, 0xff}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := checkertest.New(t, "finding")
			cfg := testResponseConfig()
			srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
			sc := MustNew(cfg)
			t.Cleanup(sc.Close)
			got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPResponse, UseBody: true, Body: tc.body})
			if got.CheckerBlocked() != tc.assess {
				t.Fatalf("assessment=%v result=%+v", tc.assess, got)
			}
			if !tc.assess {
				if len(srv.Items()) != 0 {
					t.Fatal("non-text bytes sent to checker")
				}
				return
			}
			item := srv.Items()[0]
			if !strings.Contains(item.Parts[0].Text, tc.text) || item.OriginalBytes != int64(len(tc.body)) {
				t.Fatalf("item=%+v", item)
			}
			for _, p := range item.Parts {
				if strings.Contains(p.Text, "PNG") {
					t.Fatal("image pixel container sent to checker")
				}
			}
		})
	}
}

func TestBufferedInjectionExtractionFailure(t *testing.T) {
	srv := checkertest.New(t, "benign")
	cfg := testResponseConfig()
	surface := config.InjectionSurfaceHTTPResponse
	srv.Configure(cfg, surface, config.InjectionModeBlock)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	got := sc.ComposeBufferedInjection(ctx, BufferedInjectionScan{Surface: surface, UseBody: true, Body: []byte("ordinary body")}, ResponseScanResult{Clean: true})
	if !got.Failed() || got.Clean || len(srv.Items()) != 0 {
		t.Fatalf("canceled extraction admitted: %+v", got)
	}
	got = sc.ComposeBufferedInjection(t.Context(), BufferedInjectionScan{Surface: surface, OriginalBytes: 256, Texts: []string{"extracted field"}}, ResponseScanResult{Clean: true})
	if !got.Clean || srv.Items()[0].OriginalBytes != 256 {
		t.Fatalf("source size lost: %+v", got)
	}
}

func TestBufferedInjectionCorruptMetadata(t *testing.T) {
	body := pngWithMetadata(t, "zTXt", []byte("Comment\x00\x00broken"))
	if _, err := extractResponseBodyViews(t.Context(), body); err == nil {
		t.Fatal("corrupt compressed metadata treated as empty content")
	}
}

func TestBufferedInjectionBasicPatternName(t *testing.T) {
	cfg := config.Defaults()
	cfg.ApplyDefaults()
	cfg.Internal = nil
	cfg.DLP.ScanEnv = false
	cfg.ResponseScanning.Enabled = true
	cfg.ResponseScanning.Action = config.ActionWarn
	cfg.ResponseScanning.Patterns[0].Name = CheckerPatternPrefix + "custom"
	cfg.ResponseScanning.Patterns[0].Regex = "ordinary fixture phrase"
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPResponse, Content: "ordinary fixture phrase"})
	if got.Clean || len(got.Matches) == 0 {
		t.Fatalf("control pattern did not match: %+v", got)
	}
	if got.CheckerBlocked() || HasCheckerFinding(got.Matches) || got.EnforcementAction(sc.ResponseAction()) != config.ActionWarn {
		t.Fatalf("basic name changed the configured action: %+v", got)
	}
}

func TestBufferedInjectionLatin1Metadata(t *testing.T) {
	srv := checkertest.New(t, "benign")
	cfg := testResponseConfig()
	srv.Configure(cfg, config.InjectionSurfaceHTTPResponse, config.InjectionModeBlock)
	sc := MustNew(cfg)
	t.Cleanup(sc.Close)
	body := pngWithMetadata(t, "tEXt", append([]byte("Comment\x00caf"), 0xe9))
	got := sc.ScanBufferedInjection(t.Context(), BufferedInjectionScan{Surface: config.InjectionSurfaceHTTPResponse, UseBody: true, Body: body})
	if !got.Clean || got.Failed() || got.Assessment.Status != AssessmentBenign || len(srv.Items()) != 1 {
		t.Fatalf("benign Latin-1 metadata refused: result=%+v items=%+v", got, srv.Items())
	}
	if !strings.Contains(srv.Items()[0].Parts[0].Text, "caf") {
		t.Fatal("metadata content lost")
	}
}

func TestBufferedInjectionInvalidUTF8(t *testing.T) {
	text := "ordinary" + string([]byte{0xff, 0xfe}) + "text"
	for _, surface := range bufferedTestSurfaces() {
		for _, compose := range []bool{false, true} {
			t.Run(surface+"/compose="+fmt.Sprint(compose), func(t *testing.T) {
				srv := checkertest.New(t, "benign")
				cfg := testResponseConfig()
				srv.Configure(cfg, surface, config.InjectionModeBlock)
				sc := MustNew(cfg)
				t.Cleanup(sc.Close)
				opts := BufferedInjectionScan{Surface: surface, Content: text}
				var got ResponseScanResult
				if compose {
					opts.Texts = []string{text, "ｈｅｌｌｏ" + string([]byte{0xff}) + "world"}
					got = sc.ComposeBufferedInjection(t.Context(), opts, ResponseScanResult{Clean: true})
				} else {
					got = sc.ScanBufferedInjection(t.Context(), opts)
				}
				if !got.Clean || got.Failed() || !got.RecoveryAssessment().IsBenign() {
					t.Fatalf("benign invalid-byte text refused: %+v", got)
				}
				items := srv.Items()
				if len(items) != 1 || items[0].OriginalBytes != int64(len(text)) || items[0].Parts[0].Text != "ordinary text" {
					t.Fatalf("unexpected checker items: %+v", items)
				}
				var submitted int64
				for _, part := range items[0].Parts {
					if !utf8.ValidString(part.Text) {
						t.Fatalf("invalid checker text %q", part.Text)
					}
					submitted += int64(len(part.Text))
				}
				if items[0].SubmittedBytes != submitted {
					t.Fatal("submitted byte count did not use cleaned text")
				}
			})
		}
	}
}

func TestInjectionTextPartsInvalidUTF8(t *testing.T) {
	parts := InjectionTextParts("", "a"+string([]byte{0xff, 0xfe})+"b", "ｈｅｌｌｏ"+string([]byte{0xff})+"world")
	if !hasCheckerView(parts, "a b") || !hasCheckerView(parts, "ｈｅｌｌｏ world") || !hasCheckerView(parts, "hello world") {
		t.Fatalf("unexpected cleaned parts: %+v", parts)
	}
}
