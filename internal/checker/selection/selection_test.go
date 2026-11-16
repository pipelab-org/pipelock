// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package selection

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

func protocolConfig(t *testing.T, endpoint, authEnv string) *config.Config {
	t.Helper()
	allow := true
	cfg := config.Defaults()
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{
		Checkers: map[string]config.InjectionCheckerConfig{"local": {
			Type: config.InjectionCheckerTypeProtocol, Endpoint: endpoint, AllowLoopbackHTTP: &allow, AuthorizationEnv: authEnv,
			Revision:  &config.InjectionCheckerRevision{Checker: "c", Model: "m", Adapter: "a"},
			TimeoutMS: 1000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12,
		}},
		Surfaces: map[string]config.InjectionSurfaceConfig{config.InjectionSurfaceMCPToolResult: {Checker: "local", Mode: config.InjectionModeBlock}},
	}
	return cfg
}

func testItem() checker.Item {
	return checker.Item{
		ID: "i", Kind: checker.KindText, Surface: "s", Transport: "t", Direction: "response", ExtractionVersion: "v",
		Parts: []checker.Part{{ID: "p", Role: "content", Representation: "original", Text: "hello"}}, SubmittedBytes: 5,
		Completeness: &checker.Completeness{Status: checker.Complete},
	}
}

// A protocol checker whose configured credential variable is unset reports
// every item unassessed and never sends an unauthenticated request.
func TestMissingCredentialIsUnavailableWithoutRequest(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("SELECTION_TEST_AUTH", "")
	set, err := New(protocolConfig(t, srv.URL+"/check", "SELECTION_TEST_AUTH"))
	if err != nil {
		t.Fatal(err)
	}
	b, ok := set.Decider(config.InjectionSurfaceMCPToolResult)
	if !ok {
		t.Fatal("no decider")
	}
	got := b.Checker.Check(context.Background(), testItem(), b.Policy)
	if got.State != checker.StateNotAssessed || got.Reason != checker.ReasonUnavailable || requests.Load() != 0 {
		t.Fatalf("assessment=%+v requests=%d", got, requests.Load())
	}
	off := b.Policy
	off.Mode = checker.ModeOff
	if got := b.Checker.Check(context.Background(), testItem(), off); got.State != checker.StateOff {
		t.Fatalf("off policy = %+v", got)
	}
}

func TestJevWithoutThresholdIsAnError(t *testing.T) {
	yes := true
	cfg := config.Defaults()
	cfg.PromptInjectionDetection = &config.PromptInjectionDetection{Checkers: map[string]config.InjectionCheckerConfig{"jev": {
		Type: config.InjectionCheckerTypeJev, Model: "jev-1.14.0", APIKeyEnv: "SELECTION_TEST_KEY",
		TimeoutMS: 1000, MaxRequestBytes: 1 << 16, MaxResponseBytes: 1 << 12, SendContentOffHost: &yes,
	}}}
	if _, err := New(cfg); err == nil {
		t.Fatal("jev checker without a threshold built")
	}
}

func TestWatchReportsAdmission(t *testing.T) {
	release := make(chan struct{})
	blocking := checkerFunc(func(context.Context, checker.Item, checker.Policy) checker.Assessment {
		<-release
		return checker.Assessment{State: checker.StateBenign}
	})
	s := &Set{slots: make(chan struct{}, watchSlots)}
	b := Binding{Name: "w", Checker: blocking, Watch: true}
	for i := range watchSlots {
		if !s.Watch(context.Background(), b, testItem(), nil) {
			t.Fatalf("watch %d not admitted", i)
		}
	}
	if s.Watch(context.Background(), b, testItem(), nil) || s.WatchDrops() != 1 {
		t.Fatalf("saturated watch admitted or not counted: drops=%d", s.WatchDrops())
	}
	close(release)
	s.Close()
	if s.Watch(context.Background(), b, testItem(), nil) {
		t.Fatal("watch admitted after Close")
	}
}

type checkerFunc func(context.Context, checker.Item, checker.Policy) checker.Assessment

func (f checkerFunc) Check(ctx context.Context, item checker.Item, p checker.Policy) checker.Assessment {
	return f(ctx, item, p)
}
