// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"context"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/checker/checkertest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func mockChecker(endpoint string) config.InjectionCheckerConfig {
	allow := true
	r := checkertest.MockRevision
	return config.InjectionCheckerConfig{
		Type: config.InjectionCheckerTypeProtocol, Endpoint: endpoint, AllowLoopbackHTTP: &allow,
		Revision:  &config.InjectionCheckerRevision{Checker: r.Checker, Model: r.Model, Adapter: r.Adapter},
		TimeoutMS: 2000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
	}
}

func setConfig(checkers map[string]config.InjectionCheckerConfig, surfaces map[string]config.InjectionSurfaceConfig) *config.Config {
	cfg := config.Defaults()
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Checkers: checkers, Surfaces: surfaces}
	return cfg
}

func newSet(t *testing.T, cfg *config.Config) *Set {
	t.Helper()
	s, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestBindingsPerSurface(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s := newSet(t, setConfig(
		map[string]config.InjectionCheckerConfig{"decide": mockChecker(m.URL), "watch": mockChecker(m.URL)},
		map[string]config.InjectionSurfaceConfig{
			config.InjectionSurfaceMCPToolResult:      {Checker: "decide", Mode: config.InjectionModeWarn, Watch: "watch"},
			config.InjectionSurfaceMCPToolDescription: {Checker: "decide", Mode: config.InjectionModeOff},
		}))

	b, ok := s.Decider(config.InjectionSurfaceMCPToolResult)
	if !ok || b.Name != "decide" || b.Watch || b.Policy.Mode != checker.ModeWarn {
		t.Fatalf("tool result decider = %+v, %v", b, ok)
	}
	w, ok := s.Watcher(config.InjectionSurfaceMCPToolResult)
	if !ok || w.Name != "watch" || !w.Watch || w.Policy.Mode != checker.ModeWarn {
		t.Fatalf("tool result watcher = %+v, %v", w, ok)
	}
	if !s.External(config.InjectionSurfaceMCPToolResult) || !s.Watches(config.InjectionSurfaceMCPToolResult) {
		t.Fatal("tool result surface not reported external with a watch")
	}
	// An external checker in off mode still owns the surface but decides nothing.
	if _, ok := s.Decider(config.InjectionSurfaceMCPToolDescription); ok {
		t.Fatal("off surface has a decider")
	}
	if !s.External(config.InjectionSurfaceMCPToolDescription) {
		t.Fatal("off external surface lost ownership")
	}
	if _, ok := s.Watcher(config.InjectionSurfaceMCPToolDescription); ok || s.Watches(config.InjectionSurfaceMCPToolDescription) {
		t.Fatal("surface without a watch reports one")
	}
	got := b.Checker.Check(context.Background(), probeItem("x", selfTestSuspicious), b.Policy)
	if got.State != checker.StateFinding {
		t.Fatalf("decider assessment = %+v", got)
	}
}

func TestBuiltinSurfaceHasNoExternalBinding(t *testing.T) {
	s := newSet(t, config.Defaults())
	for _, surface := range config.InjectionSurfaces() {
		if _, ok := s.Decider(surface); ok || s.External(surface) || s.Watches(surface) {
			t.Fatalf("default surface %s has an external binding", surface)
		}
	}
	if failed := s.SelfTest(context.Background()); len(failed) != 0 {
		t.Fatalf("self test with no checkers failed %v", failed)
	}
}

func TestNilSetIsInert(t *testing.T) {
	var s *Set
	if _, ok := s.Decider(config.InjectionSurfaceMCPToolResult); ok {
		t.Fatal("nil set decider")
	}
	if _, ok := s.Watcher(config.InjectionSurfaceMCPToolResult); ok {
		t.Fatal("nil set watcher")
	}
	if s.External(config.InjectionSurfaceMCPToolResult) || s.Watches(config.InjectionSurfaceMCPToolResult) {
		t.Fatal("nil set owns a surface")
	}
	if s.Watch(context.Background(), Binding{}, checker.Item{}, nil) || s.WatchDrops() != 0 || s.SelfTest(context.Background()) != nil {
		t.Fatal("nil set did work")
	}
	s.Close()
	s.dropped()
}

// gatedChecker signals when a call has started and waits for release before
// it reads the item or its context, so a test can cancel and mutate first.
type gatedChecker struct {
	started chan struct{}
	release chan struct{}
}

type gatedResult struct {
	text         string
	toolValue    string
	completeness string
	ctxErr       error
}

func (g gatedChecker) Check(ctx context.Context, item checker.Item, _ checker.Policy) checker.Assessment {
	g.started <- struct{}{}
	<-g.release
	gr := gatedResult{text: item.Parts[0].Text, toolValue: item.Context[0].Value, completeness: item.Completeness.Status, ctxErr: ctx.Err()}
	if gr.text != selfTestSuspicious || gr.toolValue != "read_file" || gr.completeness != checker.Complete || gr.ctxErr != nil {
		return checker.Assessment{State: checker.StateIncomplete}
	}
	return checker.Assessment{State: checker.StateFinding}
}

func TestWatchIsolatesCallerCancellationAndMutation(t *testing.T) {
	s := newSet(t, config.Defaults())
	// started is buffered and the gate is released at cleanup, before the
	// set's Close waits for the call, so a failed wait cannot hang the test.
	g := gatedChecker{started: make(chan struct{}, 1), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(g.release) }) }
	t.Cleanup(release)
	b := Binding{Name: "gated", Checker: g, Policy: checker.Policy{Mode: checker.ModeWarn}, Watch: true}
	item := probeItem("w", selfTestSuspicious)
	item.Context = []checker.ContextValue{{Name: "tool", Value: "read_file", Origin: checker.OriginOperator, Trust: checker.TrustAuthenticated}}
	done := make(chan checker.Assessment, 1)
	ctx, cancel := context.WithCancel(context.Background())
	if !s.Watch(ctx, b, item, func(a checker.Assessment) { done <- a }) {
		t.Fatal("watch not admitted")
	}
	select {
	case <-g.started:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("watch call never started")
	}
	// The call is parked before reading anything: cancel and mutate now.
	cancel()
	item.Parts[0].Text = "mutated"
	item.Context[0].Value = "mutated"
	item.Completeness.Status = checker.Partial
	release()
	select {
	case a := <-done:
		if a.State != checker.StateFinding {
			t.Fatalf("watch saw caller cancellation or mutation: %+v", a)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("watch result not delivered")
	}
}

func TestCloseWaitsForInFlightWatch(t *testing.T) {
	s, err := New(config.Defaults())
	if err != nil {
		t.Fatal(err)
	}
	g := gatedChecker{started: make(chan struct{}, 1), release: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(g.release) }) }
	t.Cleanup(release)
	b := Binding{Name: "gated", Checker: g, Policy: checker.Policy{Mode: checker.ModeWarn}, Watch: true}
	item := probeItem("w", selfTestSuspicious)
	item.Context = []checker.ContextValue{{Name: "tool", Value: "read_file", Origin: checker.OriginOperator, Trust: checker.TrustAuthenticated}}
	done := make(chan checker.Assessment, 1)
	if !s.Watch(context.Background(), b, item, func(a checker.Assessment) { done <- a }) {
		t.Fatal("watch not admitted")
	}
	select {
	case <-g.started:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("watch call never started")
	}

	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()
	// Once Close has stopped admission it must keep waiting while the call
	// is parked.
	testwait.For(t, testwait.Deadline(5*time.Second), func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.closed
	}, "Close never stopped admission")
	select {
	case <-closed:
		t.Fatal("Close returned while a watch call was still in flight")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	select {
	case <-closed:
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("Close did not return after the watch call finished")
	}
	select {
	case a := <-done:
		if a.State != checker.StateFinding {
			t.Fatalf("watch assessment = %+v", a)
		}
	default:
		t.Fatal("Close returned before the watch callback ran")
	}

	// Nothing is admitted after Close.
	if s.Watch(context.Background(), b, probeItem("late", selfTestBenign), nil) {
		t.Fatal("watch admitted after close")
	}
	if s.WatchDrops() != 1 {
		t.Fatalf("drops = %d, want 1", s.WatchDrops())
	}
}

func TestWatchAcceptsNilCallback(t *testing.T) {
	m := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	s := newSet(t, setConfig(
		map[string]config.InjectionCheckerConfig{"watch": mockChecker(m.URL)},
		map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: {Mode: config.InjectionModeWarn, Watch: "watch"}}))
	w, ok := s.Watcher(config.InjectionSurfaceMCPToolResult)
	if !ok {
		t.Fatal("no watcher")
	}
	if !s.Watch(context.Background(), w, probeItem("n", selfTestBenign), nil) {
		t.Fatal("nil-callback watch not admitted")
	}
	s.Close()
	if m.Requests() != 1 {
		t.Fatalf("checker saw %d requests, want 1", m.Requests())
	}
}

func TestWatchDropsWhenSlotsAreBusy(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-release
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	t.Cleanup(srv.Close)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	s := newSet(t, setConfig(
		map[string]config.InjectionCheckerConfig{"watch": mockChecker(srv.URL + "/check")},
		map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: {Mode: config.InjectionModeWarn, Watch: "watch"}}))
	w, _ := s.Watcher(config.InjectionSurfaceMCPToolResult)
	for i := range watchSlots {
		if !s.Watch(context.Background(), w, probeItem("busy", selfTestBenign), nil) {
			t.Fatalf("watch %d not admitted", i)
		}
	}
	if s.Watch(context.Background(), w, probeItem("over", selfTestBenign), nil) {
		t.Fatal("watch admitted with every slot busy")
	}
	if s.WatchDrops() != 1 {
		t.Fatalf("drops = %d, want 1", s.WatchDrops())
	}
	once.Do(func() { close(release) })
}

func TestSelfTestNamesFailingCheckers(t *testing.T) {
	good := checkertest.NewMockServer(t, checkertest.BehaviorClassify)
	down := checkertest.NewMockServer(t, checkertest.BehaviorDown)
	s := newSet(t, setConfig(map[string]config.InjectionCheckerConfig{"good": mockChecker(good.URL), "down": mockChecker(down.URL)}, nil))
	failed := s.SelfTest(context.Background())
	if !slices.Equal(failed, []string{"down"}) {
		t.Fatalf("failed = %v, want [down]", failed)
	}
	if good.Requests() != 2 {
		t.Fatalf("good checker saw %d requests, want both probes", good.Requests())
	}
}

func TestBuildOptions(t *testing.T) {
	tls := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(tls.Close)
	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: tls.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	lo, hi := 0.0, 1.0
	uid := uint32(os.Getuid()) // #nosec G115 -- test uid fits
	threshold := 0.5
	yes := true
	t.Setenv("SELECTION_TEST_AUTH", "token")

	withCA := mockChecker("https://checker.vendor.example/check")
	withCA.AllowLoopbackHTTP = nil
	withCA.CAFile = caPath
	withCA.AuthorizationEnv = "SELECTION_TEST_AUTH"
	withCA.Score = &config.InjectionCheckerScore{Scale: "prob", CalibrationID: "cal-1", Min: &lo, Max: &hi}

	unix := mockChecker("")
	unix.AllowLoopbackHTTP = nil
	unix.Endpoint = "http://localhost/check"
	unix.UnixSocket = filepath.Join(t.TempDir(), "checker.sock")
	unix.PeerUID = &uid

	jev := config.InjectionCheckerConfig{
		Type: config.InjectionCheckerTypeJev, Model: "jev-1.14.0", APIKeyEnv: "SELECTION_TEST_AUTH", Threshold: &threshold,
		TimeoutMS: 1000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12, SendContentOffHost: &yes,
	}

	s := newSet(t, setConfig(map[string]config.InjectionCheckerConfig{"ca": withCA, "unix": unix, "jev": jev}, nil))
	if p := s.policies["ca"]; p.Scale == nil || p.Scale.Name != "prob" || p.Scale.Max != 1 {
		t.Fatalf("score scale not carried: %+v", p.Scale)
	}
	if p := s.policies["jev"]; p.Revision.Adapter != checker.JevAdapter || p.Revision.Model != "jev-1.14.0" {
		t.Fatalf("jev revision = %+v", p.Revision)
	}
	for _, name := range []string{"ca", "unix", "jev"} {
		if _, ok := s.checkers[name].(unavailable); ok {
			t.Fatalf("%s built as unavailable", name)
		}
	}
}

func TestBuildRejectsUnreadableCAFile(t *testing.T) {
	bad := mockChecker("https://checker.vendor.example/check")
	bad.AllowLoopbackHTTP = nil
	bad.CAFile = filepath.Join(t.TempDir(), "missing.pem")
	if _, err := New(setConfig(map[string]config.InjectionCheckerConfig{"bad": bad}, nil)); err == nil {
		t.Fatal("checker with a missing ca_file built")
	}
}

func TestBuildRejectsInvalidClientOptions(t *testing.T) {
	bad := mockChecker("ftp://checker.vendor.example/check")
	if _, err := New(setConfig(map[string]config.InjectionCheckerConfig{"bad": bad}, nil)); err == nil {
		t.Fatal("checker with an ftp endpoint built")
	}
}
