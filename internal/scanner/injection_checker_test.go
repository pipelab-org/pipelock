// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

type checkerEvents struct {
	mu     sync.Mutex
	events []InjectionCheckerEvent
	notify chan struct{}
}

func (c *checkerEvents) hook(_ context.Context, ev InjectionCheckerEvent) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.mu.Unlock()
	select {
	case c.notify <- struct{}{}:
	default:
	}
}

func (c *checkerEvents) snapshot() []InjectionCheckerEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]InjectionCheckerEvent(nil), c.events...)
}

func (c *checkerEvents) waitFor(t *testing.T, n int) []InjectionCheckerEvent {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		if got := c.snapshot(); len(got) >= n {
			return got
		}
		select {
		case <-c.notify:
		case <-deadline:
			t.Fatalf("got %d checker events, want %d", len(c.snapshot()), n)
		}
	}
}

func checkerScanner(t *testing.T, endpoint string, surface config.InjectionSurfaceConfig) (*Scanner, *checkerEvents) {
	t.Helper()
	allow := true
	r := checkertest.MockRevision
	def := config.InjectionCheckerConfig{
		Type: config.InjectionCheckerTypeProtocol, Endpoint: endpoint, AllowLoopbackHTTP: &allow,
		Revision:  &config.InjectionCheckerRevision{Checker: r.Checker, Model: r.Model, Adapter: r.Adapter},
		TimeoutMS: 2000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
	}
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{
		Checkers: map[string]config.InjectionCheckerConfig{"decide": def, "watch": def},
		Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: surface},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	ev := &checkerEvents{notify: make(chan struct{}, 16)}
	s.SetInjectionCheckerHook(ev.hook)
	return s, ev
}

func checkerTestItem(text string) checker.Item {
	return checker.Item{
		ID: "item", Kind: checker.KindText, Surface: config.InjectionSurfaceMCPToolResult, Transport: "test", Direction: "response",
		ExtractionVersion: "test/v1",
		Parts:             []checker.Part{{ID: "p0", Role: "content", Representation: "original", Text: text}},
		OriginalBytes:     int64(len(text)), SubmittedBytes: int64(len(text)),
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
}

func TestAssessInjectionOutcomes(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s, ev := checkerScanner(t, m.URL, config.InjectionSurfaceConfig{Checker: "decide", Mode: config.InjectionModeBlock})
	ctx := context.Background()

	if !s.ExternalInjectionSurface(config.InjectionSurfaceMCPToolResult) || s.ExternalInjectionSurface(config.InjectionSurfaceMCPToolDescription) {
		t.Fatal("external surface ownership wrong")
	}

	benign, ok := s.AssessInjection(ctx, config.InjectionSurfaceMCPToolResult, checkerTestItem("plain weather report"))
	if !ok || benign.Block() || benign.Finding() || benign.Recovery().Status != AssessmentBenign || benign.Checker != "decide" {
		t.Fatalf("benign = %+v ok=%v", benign, ok)
	}
	if len(ev.snapshot()) != 0 {
		t.Fatal("benign result was reported")
	}

	found, _ := s.AssessInjection(ctx, config.InjectionSurfaceMCPToolResult, checkerTestItem(checkertest.SuspiciousMarker))
	if !found.Block() || !found.Finding() || found.Reason() != FindingReason || found.Recovery().Status != AssessmentFinding {
		t.Fatalf("finding = %+v", found)
	}
	got := ev.snapshot()
	if len(got) != 1 || got[0].State != string(checker.StateFinding) || got[0].Mode != config.InjectionModeBlock || got[0].Reason != FindingReason || got[0].Watch {
		t.Fatalf("finding event = %+v", got)
	}

	m.SetBehavior(checkertest.BehaviorDown)
	failed, _ := s.AssessInjection(ctx, config.InjectionSurfaceMCPToolResult, checkerTestItem("anything"))
	if !failed.Block() || failed.Finding() || failed.Recovery().Status != AssessmentNotAssessed || failed.Reason() != string(failed.Assessment.Reason) {
		t.Fatalf("failure = %+v", failed)
	}

	if _, ok := s.AssessInjection(ctx, config.InjectionSurfaceMCPToolDescription, checkerTestItem("x")); ok {
		t.Fatal("built-in surface returned an external assessment")
	}
}

func TestExternalAssessmentReasonAndRecovery(t *testing.T) {
	cases := []struct {
		name   string
		a      checker.Assessment
		status AssessmentStatus
		reason string
	}{
		{"uncited finding", checker.Assessment{State: checker.StateFinding, Response: &checker.Response{}}, AssessmentFinding, "suspicious"},
		{"finding without response", checker.Assessment{State: checker.StateFinding}, AssessmentFinding, "suspicious"},
		{"incomplete", checker.Assessment{State: checker.StateIncomplete}, AssessmentIncomplete, string(checker.StateIncomplete)},
		{"off", checker.Assessment{State: checker.StateOff}, AssessmentOff, string(checker.StateOff)},
		{"timeout", checker.Assessment{State: checker.StateNotAssessed, Reason: checker.ReasonTimeout}, AssessmentNotAssessed, string(checker.ReasonTimeout)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := ExternalAssessment{Checker: "c", Mode: config.InjectionModeWarn, Assessment: tc.a}
			if e.Block() {
				t.Fatal("warn mode blocked")
			}
			if got := e.Recovery(); got.Status != tc.status || got.Checker != "c" {
				t.Fatalf("recovery = %+v, want %s", got, tc.status)
			}
			if got := e.Reason(); got != tc.reason {
				t.Fatalf("reason = %q, want %q", got, tc.reason)
			}
		})
	}
}

func TestWatchInjectionReportsWithoutDeciding(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s, ev := checkerScanner(t, m.URL, config.InjectionSurfaceConfig{Mode: config.InjectionModeWarn, Watch: "watch"})

	// The built-in decides the surface; the watch runs beside it.
	if _, ok := s.AssessInjection(context.Background(), config.InjectionSurfaceMCPToolResult, checkerTestItem(checkertest.SuspiciousMarker)); ok {
		t.Fatal("watch-only surface returned a decision")
	}
	got := ev.waitFor(t, 1)
	if !got[0].Watch || got[0].Dropped || got[0].State != string(checker.StateFinding) || got[0].Reason != FindingReason || got[0].Checker != "watch" {
		t.Fatalf("watch event = %+v", got[0])
	}

	m.SetBehavior(checkertest.BehaviorDown)
	s.AssessInjection(context.Background(), config.InjectionSurfaceMCPToolResult, checkerTestItem("x"))
	got = ev.waitFor(t, 2)
	if got[1].State != string(checker.StateNotAssessed) || got[1].Reason == "" {
		t.Fatalf("failed watch event = %+v", got[1])
	}

	// After the snapshot closes, watch calls are dropped and reported.
	s.InjectionCheckers().Close()
	s.AssessInjection(context.Background(), config.InjectionSurfaceMCPToolResult, checkerTestItem("x"))
	got = ev.waitFor(t, 3)
	if !got[2].Dropped || !got[2].Watch {
		t.Fatalf("dropped watch event = %+v", got[2])
	}
}

// A watch call ignores the caller's cancellation, so an item whose build was
// canceled after it kept parts is still assessed by the watcher and its finding
// is reported, while a canceled build with nothing to send reports canceled.
func TestWatchInjectionAssessesCanceledBuildThatKeptParts(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s, ev := checkerScanner(t, m.URL, config.InjectionSurfaceConfig{Mode: config.InjectionModeWarn, Watch: "watch"})
	canceled, cancel := context.WithCancel(t.Context())
	cancel()

	item := checkerTestItem(checkertest.SuspiciousMarker)
	item.Completeness = &checker.Completeness{Status: checker.Partial, Reason: checker.ReasonCanceled}
	s.AssessInjection(canceled, config.InjectionSurfaceMCPToolResult, item)
	got := ev.waitFor(t, 1)
	if !got[0].Watch || got[0].State != string(checker.StateFinding) || got[0].Reason != FindingReason {
		t.Fatalf("canceled build that kept parts: %+v", got[0])
	}

	empty := checkerTestItem("")
	empty.Parts, empty.SubmittedBytes = nil, 0
	empty.Completeness = &checker.Completeness{Status: checker.Partial, Reason: checker.ReasonCanceled}
	s.AssessInjection(canceled, config.InjectionSurfaceMCPToolResult, empty)
	got = ev.waitFor(t, 2)
	if got[1].State != string(checker.StateNotAssessed) || got[1].Reason != string(checker.ReasonCanceled) {
		t.Fatalf("canceled build with no parts: %+v", got[1])
	}
}

func TestInjectionCheckerHookNilSafety(t *testing.T) {
	var nilScanner *Scanner
	nilScanner.ReportInjectionChecker(context.Background(), InjectionCheckerEvent{})
	if nilScanner.InjectionCheckers() != nil {
		t.Fatal("nil scanner has checkers")
	}
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s, ev := checkerScanner(t, m.URL, config.InjectionSurfaceConfig{Checker: "decide", Mode: config.InjectionModeWarn})
	s.SetInjectionCheckerHook(nil)
	s.ReportInjectionChecker(context.Background(), InjectionCheckerEvent{Checker: "x"})
	if len(ev.snapshot()) != 0 {
		t.Fatal("cleared hook still received events")
	}
}

// A checker that echoes identifier-shaped assessed content as its reason ID
// never gets that value into an event, on the deciding or the watch path.
func TestCheckerReasonIDNeverReachesEvents(t *testing.T) {
	const echoed = "secret_token_123"
	m := checkertest.NewMockServer(t, checkertest.BehaviorEchoReason)
	s, ev := checkerScanner(t, m.URL, config.InjectionSurfaceConfig{Checker: "decide", Mode: config.InjectionModeBlock, Watch: "watch"})
	out, ok := s.AssessInjection(context.Background(), config.InjectionSurfaceMCPToolResult, checkerTestItem(echoed))
	if !ok || !out.Finding() || out.Assessment.Response.Findings[0].ReasonID != echoed {
		t.Fatalf("fixture did not echo the content as the reason ID: %+v", out)
	}
	if out.Reason() != FindingReason {
		t.Fatalf("Reason() = %q, want %q", out.Reason(), FindingReason)
	}
	got := ev.waitFor(t, 2)
	sawWatch, sawDecide := false, false
	for _, e := range got {
		if e.Reason != FindingReason || strings.Contains(e.Reason+e.State+e.Mode+e.Checker, echoed) {
			t.Fatalf("event carries checker reason text: %+v", e)
		}
		sawWatch = sawWatch || e.Watch
		sawDecide = sawDecide || !e.Watch
	}
	if !sawWatch || !sawDecide {
		t.Fatalf("missing an event path: %+v", got)
	}
}
