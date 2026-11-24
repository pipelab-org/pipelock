// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type heldWireWriter func([]byte) error

func (w heldWireWriter) WriteMessage(msg []byte) error { return w(msg) }

type heldParkContext struct {
	context.Context
	parked chan struct{}
	once   sync.Once
}

func (c *heldParkContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.parked) })
	return c.Context.Done()
}

func awaitHeldTest[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("timed out waiting for held call")
		var zero T
		return zero
	}
}

type heldEvidencePoint struct {
	id, holdID, parent, phase, verdict, outcome string
	correction                                  bool
}

func holdPoint(id, parent string) heldEvidencePoint {
	return heldEvidencePoint{id: id, holdID: id, parent: parent, phase: "hold", verdict: config.ActionDefer}
}

func resolutionPoint(id, verdict string, correction bool) heldEvidencePoint {
	return heldEvidencePoint{id: id, holdID: id, phase: "resolution", verdict: verdict, correction: correction}
}

func heldAttempt(id, outcome string) []heldEvidencePoint {
	points := []heldEvidencePoint{{id: id, phase: "intent", verdict: config.ActionAllow}}
	if outcome != "" {
		verdict := config.ActionAllow
		if outcome == "not_released" {
			verdict = config.ActionBlock
		}
		points = append(points, heldEvidencePoint{id: id, phase: "outcome", verdict: verdict, outcome: outcome})
	}
	return points
}

func assertHeldEvidence(t *testing.T, actions []v3.Action, want []heldEvidencePoint) {
	t.Helper()
	ids := make(map[string]bool)
	for _, point := range want {
		ids[point.id] = true
	}
	var got []heldEvidencePoint
	for _, action := range actions {
		if !ids[action.ActionID] {
			if action.Hold != nil || action.EffectBoundary == mcpUpstreamSendBoundary {
				t.Fatalf("unexpected held or upstream action %+v", action)
			}
			continue
		}
		point := heldEvidencePoint{id: action.ActionID, phase: action.Phase, verdict: action.Verdict, outcome: action.OutcomeClass}
		if hold := action.Hold; hold != nil {
			point.holdID, point.parent = hold.ID, hold.Parent
			point.correction = hold.Correction != nil && *hold.Correction
		}
		got = append(got, point)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("held receipts:\n got %+v\nwant %+v", got, want)
	}
}

func TestMCPV3HeldRequestsAndNotifications(t *testing.T) {
	for _, surface := range []string{deferred.SurfaceMCPStdio, deferred.SurfaceMCPHTTPUpstream} {
		t.Run(surface, func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, surface)
			opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
			opts.Transport = surface
			beforePolicy := strings.Repeat("a", 64)
			afterPolicy := strings.Repeat("b", 64)
			var revisionChanged atomic.Bool
			opts.PolicyHashFn = func() string {
				if revisionChanged.Load() {
					return afterPolicy
				}
				return beforePolicy
			}
			opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
			opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			opts.WarnContext = ctx
			in, feed := io.Pipe()
			defer func() { _ = in.Close() }()
			defer func() { _ = feed.Close() }()
			observed := make(chan string, 2)
			proxyDone := make(chan error, 1)
			var proxyLog lockedHTTPBuffer
			if surface == deferred.SurfaceMCPStdio {
				peer := heldWireWriter(func(msg []byte) error {
					observed <- string(msg)
					return nil
				})
				go func() {
					ForwardScannedInput(transport.NewStdioReader(in), peer, &proxyLog, config.ActionDefer, config.ActionBlock,
						make(chan BlockedRequest, 2), nil, NewRequestTracker(), opts.withV3Session())
					proxyDone <- nil
				}()
			} else {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					msg, err := io.ReadAll(r.Body)
					if err != nil {
						t.Error(err)
						return
					}
					observed <- string(msg)
					w.WriteHeader(http.StatusAccepted)
				}))
				defer server.Close()
				go func() { proxyDone <- RunHTTPProxy(ctx, in, io.Discard, &proxyLog, server.URL, nil, opts) }()
			}
			var want []heldEvidencePoint
			messages := []string{heldNativeCall, strings.Replace(heldNativeCall, "\"id\":1,", "", 1)}
			if surface == deferred.SurfaceMCPHTTPUpstream {
				// A 202 acknowledges the send without keeping an RPC ID reserved.
				messages = append(messages, heldNativeCall)
			}
			for _, msg := range messages {
				revisionChanged.Store(false)
				if _, err := io.WriteString(feed, msg+"\n"); err != nil {
					t.Fatal(err)
				}
				testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 },
					"published v3 hold (log %s)", proxyLog.String())
				held := opts.DeferManager.Snapshot()[0]
				select {
				case sent := <-observed:
					t.Fatalf("sent before approval: %q", sent)
				default:
				}
				revisionChanged.Store(true)
				if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
					t.Fatal(err)
				}
				if sent := awaitHeldTest(t, observed); sent != msg {
					t.Fatalf("observed %q, want %q", sent, msg)
				}
				want = append(want, holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false))
				want = append(want, heldAttempt(held.ActionID, "completed")...)
			}
			if err := feed.Close(); err != nil {
				t.Fatal(err)
			}
			if err := awaitHeldTest(t, proxyDone); err != nil {
				t.Fatal(err)
			}
			actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
			assertHeldEvidence(t, actions, want)
			for _, a := range actions {
				if a.Phase != "hold" && (a.Phase != "intent" || a.EffectBoundary != mcpUpstreamSendBoundary) {
					continue
				}
				if a.Layer != mcpReceiptLayerInput || a.Pattern != "fixture hold" || a.Severity != config.SeverityHigh ||
					a.Policy.Hash != "sha256:"+beforePolicy {
					t.Errorf("%s attribution = %q/%q/%q, policy %q", a.Phase, a.Layer, a.Pattern, a.Severity, a.Policy.Hash)
				}
			}
		})
	}
}

type heldFaultFile struct {
	*os.File
	fail func(v3.Action) bool
}

func (f heldFaultFile) Write(buf []byte) (int, error) {
	envelope, code := v3.ExportDSSE(buf)
	if code == "" {
		var signed struct{ Payload []byte }
		var body struct{ Body v3.Action }
		if json.Unmarshal(envelope, &signed) == nil && json.Unmarshal(signed.Payload, &body) == nil && f.fail(body.Body) {
			return 0, errors.New("fixture action append failure")
		}
	}
	return f.File.Write(buf)
}

func heldFaultWriter(t *testing.T, fail func(v3.Action) bool) (*v3.StreamWriter, v3.StreamWriterOptions) {
	t.Helper()
	opts := mcpMatrixWriterOptions(t, v3MCPMatrixRow{required: true}, deferred.SurfaceMCPStdio, nil, nil)
	opts.CreateTempFile = func(dir, pattern string) (v3.StreamFile, error) {
		f, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return heldFaultFile{File: f, fail: fail}, nil
	}
	writer, err := v3.OpenStreamWriter(t.Context(), opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close(context.Background(), nil) })
	return writer, opts
}

func heldV3Evidence(res deferred.Resolution, id json.RawMessage, opts MCPProxyOpts) receipt.EmitOpts {
	return opts.withReceiptPolicyHash(receipt.EmitOpts{
		ActionID: res.ParentActionID, Target: firstNonEmpty(res.Target, res.Method), Method: res.Method,
		RequestID: canonicalID(id), Transport: opts.Transport, Verdict: config.ActionAllow,
		SessionID: res.Authority.SessionID, SessionIDOriginal: res.Authority.SessionIDOriginal,
	})
}

func v3ManagerAction(opts MCPProxyOpts, id string, resolve func(deferred.Resolution, deferred.Release)) deferred.HeldAction {
	held := deferred.HeldAction{
		DeferID: id, ActionID: id, Target: "echo", Method: methodToolsCall,
		Authority: deferred.AuthoritySnapshot{SessionID: "session"},
		RulePolicy: config.DeferResolutionPolicy{
			AllowOn:  config.DeferAllowOn{Approval: true, ToolInventoryBaseline: true, PolicyPermits: true},
			StepUpOn: config.DeferStepUpOn{ApprovalRequestsHuman: true},
		},
		ResolveReceipt: resolve,
	}
	opts.setupV3Hold(&held, receipt.EmitOpts{
		ActionID: id, RequestID: id, Method: methodToolsCall, Transport: opts.Transport,
		Target: "echo", Verdict: config.ActionAllow,
	})
	return held
}

type heldResolveResult struct {
	decision string
	err      error
}

func parkedV3Approval(t *testing.T, ctx context.Context, manager *deferred.Manager, id string) <-chan heldResolveResult {
	t.Helper()
	park := &heldParkContext{Context: ctx, parked: make(chan struct{})}
	outcome := make(chan heldResolveResult, 1)
	go func() {
		decision, err := manager.ResolveApprovalResultContext(park, id, config.ActionAllow, deferred.SourceOperator)
		outcome <- heldResolveResult{decision: decision, err: err}
	}()
	awaitHeldTest(t, park.parked)
	return outcome
}

func TestMCPV3HeldAncestryWitnesses(t *testing.T) {
	for _, tc := range []struct {
		route, decision, failedPhase, refusedAt, outcome string
	}{
		{route: "parent block", decision: config.ActionBlock},
		{route: "step up", decision: config.ActionStepUp},
		{route: "allow confirmation fails", failedPhase: "resolution"},
		{route: "intent confirmation fails", failedPhase: "intent"},
		{route: "pre-intent refusal", refusedAt: "before"},
		{route: "correction survives append failure", refusedAt: "before", failedPhase: "correction"},
		{route: "post-intent refusal", refusedAt: "after"},
		{route: "send observed", outcome: "completed"},
		{route: "send unknown", outcome: "attempt_unknown"},
	} {
		t.Run(tc.route, func(t *testing.T) {
			var fault atomic.Bool
			writer, writerOpts := heldFaultWriter(t, func(action v3.Action) bool {
				phase := action.Phase
				if action.Hold != nil && action.Hold.Correction != nil {
					phase = "correction"
				}
				return action.ActionID == "parent" && phase == tc.failedPhase && !fault.Swap(true)
			})
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer).withV3Session()
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			sends := make(chan string, 2)
			parentMaySend := make(chan struct{})
			allowParentSend := sync.OnceFunc(func() { close(parentMaySend) })
			defer allowParentSend()
			// The simulated peer records only actual send calls, independently of the
			// writer. Delay the parent at the boundary to allow a child to go first.
			resolve := func(id string) func(deferred.Resolution, deferred.Release) {
				return func(res deferred.Resolution, release deferred.Release) {
					if res.FinalDecision != config.ActionAllow {
						return
					}
					if id == "parent" && tc.refusedAt == "before" {
						release.Refuse("fixture_pre_intent_block", nil)
						return
					}
					evidence := heldV3Evidence(res, json.RawMessage(fmt.Sprintf("%q", id)), opts)
					exchange, err := opts.admitV3HeldSend(ctx, evidence, release)
					if err != nil {
						return
					}
					if id == "parent" && tc.refusedAt == "after" {
						opts.refuseV3HeldIntent(ctx, exchange, release)
						return
					}
					if err := opts.commitV3HeldSend(exchange, release, nil); err != nil {
						t.Errorf("commitV3HeldSend: %v", err)
					}
					observed := true
					if id == "parent" {
						select {
						case <-parentMaySend:
						case <-ctx.Done():
						}
						observed = tc.outcome == "completed"
					}
					sends <- id
					opts.confirmV3HeldSend(ctx, io.Discard, exchange, observed)
				}
			}
			for _, id := range []string{"parent", "child"} {
				if err := manager.Hold(v3ManagerAction(opts, id, resolve(id))); err != nil {
					t.Fatal(err)
				}
			}
			child := parkedV3Approval(t, ctx, manager, "child")
			select {
			case sent := <-sends:
				t.Fatalf("child reached peer before parent commitment: %s", sent)
			default:
			}
			decision := tc.decision
			if decision == "" {
				decision = config.ActionAllow
			}
			parent := make(chan heldResolveResult, 1)
			go func() {
				decision, err := manager.ResolveApprovalResultContext(ctx, "parent", decision, deferred.SourceOperator)
				parent <- heldResolveResult{decision: decision, err: err}
			}()
			childResult := awaitHeldTest(t, child)
			allowParentSend()
			parentResult := awaitHeldTest(t, parent)
			if parentResult.err != nil || childResult.err != nil {
				t.Fatalf("parent=%+v child=%+v", parentResult, childResult)
			}
			if fault.Load() != (tc.failedPhase != "") {
				t.Fatal("expected append fault did not run")
			}
			want := []heldEvidencePoint{holdPoint("parent", ""), holdPoint("child", "parent")}
			if tc.outcome != "" {
				if parentResult.decision != config.ActionAllow || childResult.decision != config.ActionAllow {
					t.Fatalf("committed branch was denied: parent=%+v child=%+v", parentResult, childResult)
				}
				if first, second := awaitHeldTest(t, sends), awaitHeldTest(t, sends); first != "child" || second != "parent" {
					t.Fatalf("peer saw %q then %q", first, second)
				}
				want = append(want, resolutionPoint("parent", config.ActionAllow, false))
				want = append(want, heldAttempt("parent", "")...)
				want = append(want, resolutionPoint("child", config.ActionAllow, false))
				want = append(want, heldAttempt("child", "completed")...)
				want = append(want, heldAttempt("parent", tc.outcome)[1])
			} else {
				wantParent := config.ActionBlock
				if tc.decision == config.ActionStepUp {
					wantParent = config.ActionAsk
				}
				if parentResult.decision != wantParent || childResult.decision != config.ActionBlock {
					t.Fatalf("parent=%+v child=%+v", parentResult, childResult)
				}
				select {
				case sent := <-sends:
					t.Fatalf("peer received blocked action %s", sent)
				default:
				}
				switch {
				case tc.refusedAt == "before":
					want = append(want, resolutionPoint("parent", config.ActionAllow, false), resolutionPoint("parent", config.ActionBlock, true))
				case tc.refusedAt == "after":
					want = append(want, resolutionPoint("parent", config.ActionAllow, false))
					want = append(want, heldAttempt("parent", "not_released")...)
				case tc.failedPhase == "intent":
					want = append(want, resolutionPoint("parent", config.ActionAllow, false), heldAttempt("parent", "not_released")[1])
				default:
					want = append(want, resolutionPoint("parent", wantParent, false))
				}
				want = append(want, resolutionPoint("child", config.ActionBlock, false))
			}
			actions := verifiedHeldActions(t, writer, writerOpts, tc.failedPhase != "")
			// A marked child's block can be confirmed before a parent's
			// independent correction. Compare each lifecycle's exact order.
			slices.SortStableFunc(actions, func(a, b v3.Action) int { return strings.Compare(a.ActionID, b.ActionID) })
			slices.SortStableFunc(want, func(a, b heldEvidencePoint) int { return strings.Compare(a.id, b.id) })
			assertHeldEvidence(t, actions, want)
		})
	}
}

func verifiedHeldActions(t *testing.T, writer *v3.StreamWriter, opts v3.StreamWriterOptions, interrupted bool) []v3.Action {
	t.Helper()
	if !interrupted {
		return verifiedMCPV3RegressionActions(t, writer, opts)
	}
	if err := writer.Close(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	key := opts.SigningKey.Public().(ed25519.PublicKey)
	result, err := v3.VerifyPaths(t.Context(), []string{opts.Dir}, v3.Options{Directory: true, Keys: []ed25519.PublicKey{key}})
	if err != nil || result.Integrity != "ok" || result.Verdict != "VALID PREFIX, END UNPROVEN" ||
		len(result.Findings) != 1 || result.Findings[0].Code != "END_UNPROVEN" {
		t.Fatalf("verify repaired stream: %+v (%v)", result, err)
	}
	actions, err := readMCPMatrixActions(opts.Dir)
	if err != nil {
		t.Fatal(err)
	}
	return actions
}

func TestMCPV3HeldConcurrentAdmissionAndCascade(t *testing.T) {
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
	opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer).withV3Session()
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute), MaxCascadeDepth: 3})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	sends := make(chan string, 4)
	resolve := func(res deferred.Resolution, release deferred.Release) {
		if res.FinalDecision == config.ActionAllow {
			sends <- res.DeferID
			release.Refuse("fixture_refusal", nil)
		}
	}
	root := v3ManagerAction(opts, "root", func(res deferred.Resolution, release deferred.Release) {
		if res.FinalDecision == config.ActionAllow {
			release.Refuse("fixture_refusal", nil)
		}
	})
	confirm := root.Receipt.ConfirmResolution
	entered, resume := make(chan struct{}), make(chan struct{})
	root.Receipt.ConfirmResolution = func(ctx context.Context, res deferred.Resolution) (string, error) {
		close(entered)
		select {
		case <-resume:
			return confirm(ctx, res)
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if err := manager.Hold(root); err != nil {
		t.Fatal(err)
	}
	rootDone := make(chan heldResolveResult, 1)
	go func() {
		decision, err := manager.ResolveApprovalResultContext(ctx, "root", config.ActionAllow, deferred.SourceOperator)
		rootDone <- heldResolveResult{decision, err}
	}()
	awaitHeldTest(t, entered)
	for _, id := range []string{"child", "grandchild"} {
		if err := manager.Hold(v3ManagerAction(opts, id, resolve)); err != nil {
			t.Fatal(err)
		}
	}
	var depthErr *deferred.CascadeLimitError
	if err := manager.Hold(v3ManagerAction(opts, "too-deep", resolve)); !errors.As(err, &depthErr) ||
		depthErr.Depth != 4 || depthErr.ParentDeferID != "grandchild" {
		t.Fatalf("concurrent admission lost its depth: %v", err)
	}
	childDone := parkedV3Approval(t, ctx, manager, "child")
	grandchildDone := parkedV3Approval(t, ctx, manager, "grandchild")
	close(resume)
	for _, result := range []heldResolveResult{awaitHeldTest(t, rootDone), awaitHeldTest(t, childDone), awaitHeldTest(t, grandchildDone)} {
		if result.decision != config.ActionBlock || result.err != nil {
			t.Fatalf("ancestry resolution: %+v", result)
		}
	}
	select {
	case sent := <-sends:
		t.Fatalf("descendant passed a closed ancestor: %s", sent)
	default:
	}
	assertSortedHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), []heldEvidencePoint{
		holdPoint("root", ""), holdPoint("child", "root"), holdPoint("grandchild", "child"),
		resolutionPoint("root", config.ActionAllow, false), resolutionPoint("root", config.ActionBlock, true),
		resolutionPoint("child", config.ActionBlock, false), resolutionPoint("grandchild", config.ActionBlock, false),
	})
}

func assertSortedHeldEvidence(t *testing.T, actions []v3.Action, want []heldEvidencePoint) {
	t.Helper()
	slices.SortStableFunc(actions, func(a, b v3.Action) int { return strings.Compare(a.ActionID, b.ActionID) })
	slices.SortStableFunc(want, func(a, b heldEvidencePoint) int { return strings.Compare(a.id, b.id) })
	assertHeldEvidence(t, actions, want)
}

func TestMCPV3HeldSiblingsAndSweeps(t *testing.T) {
	for _, sweep := range []string{"inventory", "reload"} {
		t.Run(sweep, func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer).withV3Session()
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			const parent, sibling, child = "z-parent", "sibling", "a-child"
			sends := make(chan string, 2)
			parentConfirmed := make(chan struct{})
			resolve := func(res deferred.Resolution, release deferred.Release) {
				if res.FinalDecision != config.ActionAllow {
					return
				}
				id := res.DeferID
				if id == child {
					<-parentConfirmed
				}
				evidence := heldV3Evidence(res, json.RawMessage(fmt.Sprintf("%q", id)), opts)
				exchange, err := opts.admitV3HeldSend(t.Context(), evidence, release)
				if err != nil {
					t.Error(err)
					return
				}
				if err := opts.commitV3HeldSend(exchange, release, nil); err != nil {
					t.Errorf("commitV3HeldSend: %v", err)
				}
				opts.confirmV3HeldSend(t.Context(), io.Discard, exchange, true)
				sends <- id
				if id == parent {
					close(parentConfirmed)
				}
			}
			root := v3ManagerAction(opts, parent, resolve)
			root.RulePolicy.AllowOn.ToolInventoryBaseline = false
			if err := manager.Hold(root); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{sibling, child} {
				if err := manager.Hold(v3ManagerAction(opts, id, resolve)); err != nil {
					t.Fatal(err)
				}
				if id == sibling {
					if err := manager.Resolve(id, config.ActionBlock, deferred.SourceOperator); err != nil {
						t.Fatal(err)
					}
				}
			}
			runSweep := func() {
				done := make(chan struct{})
				go func() {
					defer close(done)
					if sweep == "inventory" {
						manager.ResolveToolInventory("session", config.ActionAllow)
					} else {
						manager.ResolvePolicyReload(func(held deferred.HeldAction) (string, error) {
							if held.DeferID == parent {
								return config.ActionDefer, nil
							}
							return config.ActionAllow, nil
						})
					}
				}()
				awaitHeldTest(t, done)
			}
			runSweep()
			if len(sends) != 0 || manager.HeldCount() != 2 {
				t.Fatal("sweep released unresolved lineage")
			}
			if err := manager.Resolve(parent, config.ActionAllow, deferred.SourceOperator); err != nil {
				t.Fatal(err)
			}
			if got := []string{awaitHeldTest(t, sends), awaitHeldTest(t, sends)}; !slices.Equal(got, []string{parent, child}) {
				t.Fatalf("peer observed %v", got)
			}
			want := []heldEvidencePoint{
				holdPoint(parent, ""), holdPoint(sibling, parent), resolutionPoint(sibling, config.ActionBlock, false),
				holdPoint(child, parent), resolutionPoint(parent, config.ActionAllow, false),
			}
			want = append(want, heldAttempt(parent, "completed")...)
			want = append(want, resolutionPoint(child, config.ActionAllow, false))
			want = append(want, heldAttempt(child, "completed")...)
			assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), want)
		})
	}
}

func TestMCPV3HeldParkedCancellationAndKill(t *testing.T) {
	for _, source := range []string{deferred.SourceCancel, deferred.SourceKillSwitch, deferred.SourceOperator} {
		t.Run(source, func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			manager := deferred.NewManager(deferred.Config{
				Enabled: true, Timeout: testwait.Deadline(time.Minute), MaxPending: 2, MaxPendingPerSession: 2, MaxPendingBytes: 8,
			})
			var sends atomic.Int64
			resolve := func(res deferred.Resolution, _ deferred.Release) {
				if res.FinalDecision == config.ActionAllow {
					sends.Add(1)
				}
			}
			for _, id := range []string{"parent", "child"} {
				held := v3ManagerAction(opts, id, resolve)
				held.SizeBytes = 4
				if err := manager.Hold(held); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := parkedV3Approval(t, ctx, manager, "child")
			if err := manager.Hold(v3ManagerAction(opts, "overflow", resolve)); !errors.Is(err, deferred.ErrCapacity) {
				t.Fatalf("parked child dropped capacity: %v", err)
			}
			if source == deferred.SourceOperator {
				cancel()
				if result := awaitHeldTest(t, done); !errors.Is(result.err, context.Canceled) || manager.HeldCount() != 2 {
					t.Fatalf("cancellation took the hold: %+v", result)
				}
				if err := manager.Resolve("child", config.ActionBlock, source); err != nil {
					t.Fatal(err)
				}
				retry := v3ManagerAction(opts, "retry", resolve)
				retry.SizeBytes = 4
				if err := manager.Hold(retry); err != nil {
					t.Fatalf("settlement leaked the byte reservation: %v", err)
				}
				manager.ResolveAll(config.ActionBlock, source)
			} else {
				manager.ResolveAll(config.ActionBlock, source)
				result := awaitHeldTest(t, done)
				if result.decision != config.ActionBlock && !errors.Is(result.err, deferred.ErrNotFound) {
					t.Fatalf("parked allow did not close: %+v", result)
				}
			}
			if sends.Load() != 0 || manager.HeldCount() != 0 {
				t.Fatalf("closed fixture sent %d, held %d", sends.Load(), manager.HeldCount())
			}
			want := []heldEvidencePoint{
				holdPoint("parent", ""), holdPoint("child", "parent"),
				resolutionPoint("parent", config.ActionBlock, false), resolutionPoint("child", config.ActionBlock, false),
			}
			if source == deferred.SourceOperator {
				want = append(want, holdPoint("retry", "parent"), resolutionPoint("retry", config.ActionBlock, false))
			}
			assertSortedHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), want)
		})
	}
}

func TestMCPV3HeldCapacityDuringSettlement(t *testing.T) {
	for _, limits := range []deferred.Config{
		{MaxPending: 1},
		{MaxPendingPerSession: 1},
		{MaxPendingBytes: 8},
	} {
		t.Run(fmt.Sprintf("%d-%d-%d", limits.MaxPending, limits.MaxPendingPerSession, limits.MaxPendingBytes), func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			limits.Enabled, limits.Timeout = true, testwait.Deadline(time.Minute)
			manager := deferred.NewManager(limits)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			settling, resume := make(chan struct{}), make(chan struct{})
			held := v3ManagerAction(opts, "settling", func(res deferred.Resolution, _ deferred.Release) {
				if res.FinalDecision == config.ActionAllow {
					t.Error("block callback was opened")
				}
				close(settling)
				select {
				case <-resume:
				case <-ctx.Done():
				}
			})
			held.SizeBytes = 8
			if err := manager.Hold(held); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- manager.Resolve(held.DeferID, config.ActionBlock, deferred.SourceOperator) }()
			awaitHeldTest(t, settling)
			retry := v3ManagerAction(opts, "retry", func(res deferred.Resolution, _ deferred.Release) {
				if res.FinalDecision != config.ActionBlock {
					t.Error("unexpected send")
				}
			})
			retry.SizeBytes = 8
			if err := manager.Hold(retry); !errors.Is(err, deferred.ErrCapacity) {
				t.Fatalf("settling hold lost capacity: %v", err)
			}
			close(resume)
			if err := awaitHeldTest(t, done); err != nil {
				t.Fatal(err)
			}
			if err := manager.Hold(retry); err != nil {
				t.Fatalf("settlement leaked capacity: %v", err)
			}
			manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
			assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), []heldEvidencePoint{
				holdPoint("settling", ""), resolutionPoint("settling", config.ActionBlock, false),
				holdPoint("retry", ""), resolutionPoint("retry", config.ActionBlock, false),
			})
		})
	}
}

func TestMCPV3HeldCorrelationBeginsAtCommit(t *testing.T) {
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
	opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer).withV3Session()
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
	tracker := NewRequestTracker()
	requestID := json.RawMessage("1")
	var sends []string
	held := v3ManagerAction(opts, "held", func(res deferred.Resolution, release deferred.Release) {
		var ready atomic.Bool
		tracker.TrackOutcome(requestID, TrackedRequestOutcome{readyToCorrelate: &ready})
		exchange, err := opts.admitV3HeldSend(t.Context(), heldV3Evidence(res, requestID, opts), release)
		if err != nil {
			t.Error(err)
			return
		}
		if _, ok := tracker.Consume(requestID); ok || opts.takeV3Send(requestID) != nil {
			t.Error("an early reply claimed a held request that had not committed")
		}
		if err := opts.commitV3HeldSend(exchange, release, &ready); err != nil {
			t.Errorf("commitV3HeldSend: %v", err)
		}
		sends = append(sends, res.DeferID)
		if _, ok := tracker.Consume(requestID); !ok || opts.takeV3Send(requestID) != exchange {
			t.Error("the committed request lost its reply correlation")
		}
		opts.confirmV3HeldSend(t.Context(), io.Discard, exchange, true)
	})
	if err := manager.Hold(held); err != nil {
		t.Fatal(err)
	}
	if err := manager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(sends, []string{held.DeferID}) {
		t.Fatalf("observed send log: %v", sends)
	}
	want := []heldEvidencePoint{holdPoint("held", ""), resolutionPoint("held", config.ActionAllow, false)}
	assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), append(want, heldAttempt("held", "completed")...))
}

func TestMCPV3HeldChildTimesOutWhileParked(t *testing.T) {
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
	opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
	manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Second)})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	gate, finish := make(chan struct{}), make(chan struct{})
	parent := v3ManagerAction(opts, "parent", func(res deferred.Resolution, release deferred.Release) {
		if res.FinalDecision != config.ActionAllow {
			t.Error("parent did not reach the pre-intent gate")
			return
		}
		close(gate)
		select {
		case <-finish:
		case <-ctx.Done():
		}
		release.Refuse("fixture_refusal", nil)
	})
	if err := manager.Hold(parent); err != nil {
		t.Fatal(err)
	}
	parentDone := make(chan error, 1)
	go func() { parentDone <- manager.Resolve(parent.DeferID, config.ActionAllow, deferred.SourceOperator) }()
	awaitHeldTest(t, gate)
	childResolution := make(chan deferred.Resolution, 1)
	child := v3ManagerAction(opts, "child", func(res deferred.Resolution, _ deferred.Release) { childResolution <- res })
	if err := manager.Hold(child); err != nil {
		t.Fatal(err)
	}
	result := parkedV3Approval(t, ctx, manager, child.DeferID)
	if got := awaitHeldTest(t, childResolution); got.FinalDecision != config.ActionBlock || got.ResolutionSource != deferred.SourceTimeout {
		t.Fatalf("timeout resolution = %+v", got)
	}
	if got := awaitHeldTest(t, result); got.decision != config.ActionBlock && !errors.Is(got.err, deferred.ErrNotFound) {
		t.Fatalf("child stayed parked: %+v", got)
	}
	close(finish)
	if err := awaitHeldTest(t, parentDone); err != nil {
		t.Fatal(err)
	}
	assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), []heldEvidencePoint{
		holdPoint("parent", ""), resolutionPoint("parent", config.ActionAllow, false),
		holdPoint("child", "parent"), resolutionPoint("child", config.ActionBlock, false),
		resolutionPoint("parent", config.ActionBlock, true),
	})
}

func TestMCPV3HeldBridgeChildBeforeParentHeaders(t *testing.T) {
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPHTTPUpstream)
	opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
	opts.Transport = deferred.SurfaceMCPHTTPUpstream
	opts.PolicyCfg = deferApprovalPolicy(config.DeferResolverProfile{})
	opts.PolicyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	parentHeaders := make(chan struct{})
	finishParent := sync.OnceFunc(func() { close(parentHeaders) })
	seen := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		id := canonicalID(ParseMCPFrame(body).ID)
		seen <- id
		if id == "1" {
			select {
			case <-parentHeaders:
			case <-r.Context().Done():
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()
	defer finishParent()
	in, feed := io.Pipe()
	defer func() { _ = in.Close(); _ = feed.Close() }()
	done := make(chan error, 1)
	var proxyLog lockedHTTPBuffer
	go func() { done <- RunHTTPProxy(ctx, in, io.Discard, &proxyLog, server.URL, nil, opts) }()
	parentMessage := strings.Replace(heldNativeCall, `"echo"`, `"send_tool"`, 1)
	childMessage := strings.Replace(parentMessage, `"id":1`, `"id":2`, 1)
	if _, err := io.WriteString(feed, parentMessage+"\n"+childMessage+"\n"); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 2 }, "parent and child holds")
	held := opts.DeferManager.Snapshot()
	slices.SortFunc(held, func(a, b deferred.HeldAction) int { return a.CascadeDepth - b.CascadeDepth })
	parent, child := held[0].ActionID, held[1].ActionID
	childDone := parkedV3Approval(t, ctx, opts.DeferManager, child)
	parentDone := make(chan error, 1)
	go func() { parentDone <- opts.DeferManager.Resolve(parent, config.ActionAllow, deferred.SourceOperator) }()
	wireIDs := []string{awaitHeldTest(t, seen), awaitHeldTest(t, seen)}
	slices.Sort(wireIDs)
	if !slices.Equal(wireIDs, []string{"1", "2"}) {
		t.Fatalf("upstream reached %v before parent headers", wireIDs)
	}
	if childResult := awaitHeldTest(t, childDone); childResult.decision != config.ActionAllow || childResult.err != nil {
		t.Fatalf("child resolution = %+v", childResult)
	}
	finishParent()
	if err := awaitHeldTest(t, parentDone); err != nil {
		t.Fatal(err)
	}
	if err := feed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitHeldTest(t, done); err != nil {
		t.Fatal(err)
	}
	want := []heldEvidencePoint{holdPoint(parent, ""), holdPoint(child, parent), resolutionPoint(parent, config.ActionAllow, false)}
	want = append(want, heldAttempt(parent, "")...)
	want = append(want, resolutionPoint(child, config.ActionAllow, false))
	want = append(want, heldAttempt(child, "completed")...)
	want = append(want, heldAttempt(parent, "completed")[1])
	assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), want)
}

func TestMCPV3HeldStdioReleaseFailures(t *testing.T) {
	for _, failure := range []string{"duplicate", "intent", "send"} {
		t.Run(failure, func(t *testing.T) {
			writer, writerOpts := heldFaultWriter(t, func(a v3.Action) bool {
				return failure == "intent" && a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary
			})
			opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer).withV3Session()
			opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
			opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			opts.WarnContext = ctx
			tracker := NewRequestTracker()
			if failure == "duplicate" {
				tracker.Track(json.RawMessage("1"))
			}
			in, feed := io.Pipe()
			defer func() { _ = in.Close(); _ = feed.Close() }()
			sends, denied, done := make(chan string, 1), make(chan BlockedRequest, 1), make(chan struct{})
			peer := heldWireWriter(func(msg []byte) error {
				sends <- string(msg)
				return io.ErrClosedPipe
			})
			go func() {
				defer close(done)
				ForwardScannedInput(transport.NewStdioReader(in), peer, io.Discard, config.ActionDefer, config.ActionBlock,
					denied, nil, tracker, opts)
			}()
			if _, err := io.WriteString(feed, heldNativeCall+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "held request")
			held := opts.DeferManager.Snapshot()[0]
			if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
				t.Fatal(err)
			}
			refusal := awaitHeldTest(t, denied)
			if canonicalID(refusal.ID) != "1" || refusal.ErrorCode == 0 {
				t.Fatalf("unexpected client error: %+v", refusal)
			}
			if err := feed.Close(); err != nil {
				t.Fatal(err)
			}
			awaitHeldTest(t, done)
			want := []heldEvidencePoint{holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false)}
			switch failure {
			case "send":
				if msg := awaitHeldTest(t, sends); msg != heldNativeCall {
					t.Fatalf("peer saw %q", msg)
				}
				want = append(want, heldAttempt(held.ActionID, "attempt_unknown")...)
				out := heldWireWriter(func(msg []byte) error {
					if !strings.Contains(string(msg), "upstream write failed") {
						t.Fatalf("unexpected downstream reply: %s", msg)
					}
					return nil
				})
				if err := deliverMCPInputResult(opts, refusal, opts.v3SendDenialWriter(out, io.Discard, refusal)); err != nil {
					t.Fatal(err)
				}
			case "intent":
				want = append(want, heldAttempt(held.ActionID, "not_released")[1])
			case "duplicate":
				want = append(want, resolutionPoint(held.ActionID, config.ActionBlock, true))
			}
			if len(sends) != 0 {
				t.Fatal("refused held bytes reached the peer")
			}
			actions := verifiedHeldActions(t, writer, writerOpts, failure == "intent")
			assertHeldEvidence(t, actions, want)
			if failure == "send" {
				assertHeldReplyParent(t, actions, held.ActionID)
			}
		})
	}
}

func assertHeldReplyParent(t *testing.T, actions []v3.Action, parent string) {
	t.Helper()
	var phases []string
	for _, a := range actions {
		if a.EffectBoundary != mcpDownstreamDeliveryBoundary || (a.Phase != "intent" && a.Phase != "outcome") {
			continue
		}
		if a.ParentActionID != parent {
			t.Fatalf("held error reply %s has parent %q, want %q", a.Phase, a.ParentActionID, parent)
		}
		phases = append(phases, a.Phase)
	}
	if !slices.Equal(phases, []string{"intent", "outcome"}) {
		t.Fatalf("held error reply receipt phases: %v, want [intent outcome]", phases)
	}
}

func TestMCPV3HeldBridgeIntentFailure(t *testing.T) {
	writer, writerOpts := heldFaultWriter(t, func(a v3.Action) bool {
		return a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary
	})
	opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
	opts.Transport = deferred.SurfaceMCPHTTPUpstream
	opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	in, feed := io.Pipe()
	defer func() { _ = in.Close(); _ = feed.Close() }()
	var sends atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		sends.Add(1)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	var output lockedHTTPBuffer
	done := make(chan error, 1)
	go func() { done <- RunHTTPProxy(ctx, in, &output, io.Discard, upstream.URL, nil, opts) }()
	if _, err := io.WriteString(feed, heldNativeCall+"\n"); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "held HTTP request")
	held := opts.DeferManager.Snapshot()[0]
	if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
		t.Fatal(err)
	}
	if err := feed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitHeldTest(t, done); err != nil {
		t.Fatal(err)
	}
	if sends.Load() != 0 {
		t.Fatal("failed intent reached the upstream")
	}
	var reply rpcError
	if err := json.Unmarshal([]byte(output.String()), &reply); err != nil || canonicalID(reply.ID) != "1" || reply.Error.Code == 0 {
		t.Fatalf("client did not receive the failed-admission error: %q (%v)", output.String(), err)
	}
	want := []heldEvidencePoint{
		holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false),
		heldAttempt(held.ActionID, "not_released")[1],
	}
	assertHeldEvidence(t, verifiedHeldActions(t, writer, writerOpts, true), want)
}

func TestMCPV3HeldRejectedAdmissionEvidence(t *testing.T) {
	for _, cause := range []error{deferred.ErrCapacity, deferred.ErrCascadeLimit, context.Canceled, v3.ErrEffectNotReleased, v3.ErrActionPersistStarted} {
		t.Run(cause.Error(), func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			held := holdFailureResolution{DeferID: "rejected", Method: methodToolsCall, Target: "echo"}
			_, err := emitHoldFailureResolution(opts, io.Discard, cause, held)
			if errors.Is(cause, v3.ErrActionPersistStarted) != (err != nil) {
				t.Fatalf("failed hold settlement returned %v", err)
			}
			actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
			var want []heldEvidencePoint
			// The writer owns repair after a started persistence attempt.
			if !errors.Is(cause, v3.ErrEffectNotReleased) && !errors.Is(cause, v3.ErrActionPersistStarted) {
				want = []heldEvidencePoint{{id: held.DeferID, phase: "decision", verdict: config.ActionBlock}}
			}
			assertHeldEvidence(t, actions, want)
		})
	}
}

func TestMCPV3HeldCancellationBeforeAllowPersistence(t *testing.T) {
	for _, failBlock := range []bool{false, true} {
		t.Run(fmt.Sprint(failBlock), func(t *testing.T) {
			writer, writerOpts := heldFaultWriter(t, func(a v3.Action) bool {
				return failBlock && a.Phase == "resolution" && a.Verdict == config.ActionBlock
			})
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			approvalCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var sent bool
			held := v3ManagerAction(opts, "cancelled", func(res deferred.Resolution, _ deferred.Release) {
				sent = res.FinalDecision == config.ActionAllow
			})
			held.BeforeAllow = func() (func(), bool) {
				cancel()
				return func() {}, true
			}
			if err := manager.Hold(held); err != nil {
				t.Fatal(err)
			}
			applied, err := manager.ResolveApprovalResultContext(approvalCtx, held.DeferID, config.ActionAllow, deferred.SourceOperator)
			want := []heldEvidencePoint{holdPoint(held.ActionID, "")}
			if failBlock {
				if err == nil || applied != "" {
					t.Fatalf("unsettled cancellation reported an applied decision: %q %v", applied, err)
				}
			} else {
				if err != nil || applied != config.ActionBlock {
					t.Fatalf("durable cancellation did not report its block: %q %v", applied, err)
				}
				want = append(want, resolutionPoint(held.ActionID, config.ActionBlock, false))
			}
			if sent {
				t.Fatal("cancelled approval sent a payload")
			}
			assertHeldEvidence(t, verifiedHeldActions(t, writer, writerOpts, failBlock), want)
		})
	}
}

func TestMCPV3HeldClosureDuringAdmission(t *testing.T) {
	for _, shutdown := range []bool{false, true} {
		t.Run(fmt.Sprint(shutdown), func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			resolved := make(chan deferred.Resolution, 2)
			captureResolution := func(res deferred.Resolution, _ deferred.Release) { resolved <- res }
			parent := v3ManagerAction(opts, "parent", captureResolution)
			if err := manager.Hold(parent); err != nil {
				t.Fatal(err)
			}
			entered, confirm := make(chan struct{}), make(chan struct{})
			finish := sync.OnceFunc(func() { close(confirm) })
			defer finish()
			child := v3ManagerAction(opts, "child", captureResolution)
			recordHold := child.Receipt.ConfirmHold
			child.Receipt.ConfirmHold = func(ctx context.Context, held deferred.HeldAction) error {
				close(entered)
				select {
				case <-confirm:
					return recordHold(ctx, held)
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			admitted := make(chan error, 1)
			go func() { admitted <- manager.HoldContext(ctx, child) }()
			awaitHeldTest(t, entered)
			childSource := deferred.SourceCascade
			if shutdown {
				manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
				childSource = deferred.SourceCancel
			} else if err := manager.Resolve(parent.DeferID, config.ActionBlock, deferred.SourceOperator); err != nil {
				t.Fatal(err)
			}
			finish()
			if err := awaitHeldTest(t, admitted); err != nil {
				t.Fatal(err)
			}
			parentResult, childResult := awaitHeldTest(t, resolved), awaitHeldTest(t, resolved)
			if parentResult.DeferID != parent.DeferID || parentResult.FinalDecision != config.ActionBlock ||
				childResult.DeferID != child.DeferID || childResult.FinalDecision != config.ActionBlock ||
				childResult.ParentDeferID != parent.DeferID || childResult.ResolutionSource != childSource {
				t.Fatalf("manager callbacks: parent=%+v child=%+v", parentResult, childResult)
			}
			assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), []heldEvidencePoint{
				holdPoint(parent.ActionID, ""), resolutionPoint(parent.ActionID, config.ActionBlock, false),
				holdPoint(child.ActionID, parent.DeferID), resolutionPoint(child.ActionID, config.ActionBlock, false),
			})
		})
	}
}

func TestMCPV3HeldSessionSettleDoesNotMisreportReservedExchange(t *testing.T) {
	for _, duringAdmit := range []bool{false, true} {
		t.Run(fmt.Sprintf("during_admit=%t", duringAdmit), func(t *testing.T) {
			writingIntent, continueIntent := make(chan struct{}), make(chan struct{})
			resumeIntent := sync.OnceFunc(func() { close(continueIntent) })
			defer resumeIntent()
			writer, writerOpts := heldFaultWriter(t, func(a v3.Action) bool {
				if duringAdmit && a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary {
					close(writingIntent)
					<-continueIntent
				}
				return false
			})
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer).withV3Session()
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			requestID := json.RawMessage("1")

			held := v3ManagerAction(opts, "reserved-teardown", func(res deferred.Resolution, release deferred.Release) {
				if res.FinalDecision != config.ActionAllow {
					t.Errorf("unexpected resolution %+v", res)
					return
				}
				if duringAdmit {
					type admissionResult struct {
						exchange *mcpV3Exchange
						err      error
					}
					result := make(chan admissionResult, 1)
					go func() {
						exchange, err := opts.admitV3HeldSend(t.Context(), heldV3Evidence(res, requestID, opts), release)
						result <- admissionResult{exchange: exchange, err: err}
					}()
					awaitHeldTest(t, writingIntent)
					opts.v3Session.mu.Lock()
					reserved := opts.v3Session.pending[canonicalID(requestID)]
					opts.v3Session.mu.Unlock()
					if reserved == nil {
						t.Error("intent persistence started without reserving the exchange")
					}
					opts.settleV3Session(t.Context(), io.Discard)
					resumeIntent()
					got := awaitHeldTest(t, result)
					if got.exchange != nil || !errors.Is(got.err, context.Canceled) {
						t.Errorf("admission across session settle = %p, %v; want nil, context.Canceled", got.exchange, got.err)
						if got.exchange != nil {
							opts.refuseV3HeldIntent(t.Context(), got.exchange, release)
						}
					}
					return
				}
				exchange, err := opts.admitV3HeldSend(t.Context(), heldV3Evidence(res, requestID, opts), release)
				if err != nil {
					t.Errorf("admitV3HeldSend: %v", err)
					return
				}
				// Session teardown runs while the held send is still reserved (pre-commit).
				// It must not settle the unsent intent as attempt_unknown, and the
				// held send must not commit afterwards.
				opts.settleV3Session(t.Context(), io.Discard)
				if err := opts.commitV3HeldSend(exchange, release, nil); !errors.Is(err, errMCPV3SessionClosed) {
					t.Errorf("commit after session settle = %v, want %v", err, errMCPV3SessionClosed)
				}
				opts.refuseV3HeldIntent(t.Context(), exchange, release)
			})
			if err := manager.Hold(held); err != nil {
				t.Fatal(err)
			}
			applied, err := manager.ResolveApprovalResultContext(t.Context(), held.DeferID, config.ActionAllow, deferred.SourceOperator)
			if err != nil || applied != config.ActionBlock {
				t.Fatalf("resolve = %q, %v; want block, nil", applied, err)
			}
			want := []heldEvidencePoint{holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false)}
			want = append(want, heldAttempt(held.ActionID, "not_released")...)
			assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), want)
		})
	}
}

func TestMCPV3HeldSendRefusalDownstreamEvidence(t *testing.T) {
	t.Run("stdio_notification_refusal_emits_no_downstream_decision", func(t *testing.T) {
		writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
		opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer).withV3Session()
		opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
		opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		opts.WarnContext = ctx

		in, feed := io.Pipe()
		defer func() { _ = in.Close(); _ = feed.Close() }()
		blockedCh := make(chan BlockedRequest, 2)
		var out lockedHTTPBuffer
		wireOut := newMCPClientWriter(&out, opts)
		blockedDone := make(chan struct{})
		go func() {
			defer close(blockedDone)
			for blocked := range blockedCh {
				_ = deliverMCPInputResult(opts, blocked, opts.v3SendDenialWriter(wireOut, io.Discard, blocked))
			}
		}()

		var sends atomic.Int64
		peer := heldWireWriter(func([]byte) error {
			sends.Add(1)
			return nil
		})
		inputDone := make(chan struct{})
		go func() {
			defer close(inputDone)
			ForwardScannedInput(transport.NewStdioReader(in), peer, io.Discard, config.ActionDefer, config.ActionBlock,
				blockedCh, nil, NewRequestTracker(), opts)
		}()

		notification := strings.Replace(heldNativeCall, "\"id\":1,", "", 1)
		if _, err := io.WriteString(feed, notification+"\n"); err != nil {
			t.Fatal(err)
		}
		testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "held notification")
		held := opts.DeferManager.Snapshot()[0]
		cancel()
		if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
			t.Fatalf("resolve held notification: %v", err)
		}
		_ = feed.Close()
		awaitHeldTest(t, inputDone)
		awaitHeldTest(t, blockedDone)
		if sends.Load() != 0 {
			t.Fatal("refused notification reached peer")
		}
		actions := verifiedMCPV3RegressionActions(t, writer, writerOpts)
		for _, a := range actions {
			if a.EffectBoundary == mcpDownstreamDeliveryBoundary {
				t.Fatalf("refused held notification emitted unexpected downstream_delivery action: %+v", a)
			}
		}
	})

	for _, tc := range []struct {
		name, message string
		handler       http.HandlerFunc
	}{
		{name: "send", message: "upstream HTTP request failed", handler: func(http.ResponseWriter, *http.Request) {
			panic(http.ErrAbortHandler)
		}},
		{name: "response", message: "upstream HTTP response failed", handler: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", "128")
			if _, err := io.WriteString(w, "{"); err != nil {
				t.Error(err)
			}
		}},
		{name: "timeout", message: "upstream response timeout", handler: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/event-stream")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
			}
			<-r.Context().Done()
		}},
	} {
		t.Run("bridge_"+tc.name+"_failure_links_error_reply_to_held_send", func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPHTTPUpstream)
			opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
			opts.Transport = deferred.SurfaceMCPHTTPUpstream
			opts.InputCfg.ResponseTimeoutSeconds = 1
			opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
			opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			in, feed := io.Pipe()
			defer func() { _ = in.Close(); _ = feed.Close() }()
			upstream := httptest.NewServer(tc.handler)
			upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
			defer upstream.Close()
			var out lockedHTTPBuffer
			done := make(chan error, 1)
			go func() { done <- RunHTTPProxy(ctx, in, &out, io.Discard, upstream.URL, nil, opts) }()
			if _, err := io.WriteString(feed, heldNativeCall+"\n"); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "held bridge call")
			held := opts.DeferManager.Snapshot()[0]
			if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
				t.Fatal(err)
			}
			testwait.For(t, 5*time.Second, func() bool { return strings.Contains(out.String(), tc.message) }, "error reply")
			_ = feed.Close()
			if err := awaitHeldTest(t, done); err != nil {
				t.Fatal(err)
			}
			assertHeldReplyParent(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), held.ActionID)
		})
	}

	t.Run("bridge_intent_failure_links_error_reply_without_duplicate_decision", func(t *testing.T) {
		writer, writerOpts := heldFaultWriter(t, func(a v3.Action) bool {
			return a.Phase == "intent" && a.EffectBoundary == mcpUpstreamSendBoundary
		})
		opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
		opts.Transport = deferred.SurfaceMCPHTTPUpstream
		opts.ListenerShutdownTimeout = testwait.Deadline(time.Second)
		opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		in, feed := io.Pipe()
		defer func() { _ = in.Close(); _ = feed.Close() }()
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusAccepted)
		}))
		defer upstream.Close()
		var out lockedHTTPBuffer
		done := make(chan error, 1)
		go func() { done <- RunHTTPProxy(ctx, in, &out, io.Discard, upstream.URL, nil, opts) }()
		if _, err := io.WriteString(feed, heldNativeCall+"\n"); err != nil {
			t.Fatal(err)
		}
		testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 1 }, "held bridge call")
		held := opts.DeferManager.Snapshot()[0]
		if err := opts.DeferManager.Resolve(held.DeferID, config.ActionAllow, deferred.SourceOperator); err != nil {
			t.Fatal(err)
		}
		_ = feed.Close()
		if err := awaitHeldTest(t, done); err != nil {
			t.Fatal(err)
		}
		actions := verifiedHeldActions(t, writer, writerOpts, true)
		var downstream []v3.Action
		for _, a := range actions {
			if a.EffectBoundary == mcpDownstreamDeliveryBoundary {
				downstream = append(downstream, a)
			}
		}
		if len(downstream) != 2 || downstream[0].Phase != "intent" || downstream[1].Phase != "outcome" ||
			downstream[0].ParentActionID != held.ActionID || downstream[1].ParentActionID != held.ActionID {
			t.Fatalf("unexpected downstream_delivery records for refused held bridge call: %+v", downstream)
		}
	})
}

func TestMCPV3HeldBridgePOSTOwnsResponse(t *testing.T) {
	const parentID, childID = "1", "2"
	writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPHTTPUpstream)
	opts := nativeDeferredOptions(t, nil).WithV3ReceiptWriter(writer)
	opts.Transport = deferred.SurfaceMCPHTTPUpstream
	opts.PolicyCfg = deferApprovalPolicy(config.DeferResolverProfile{})
	opts.PolicyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	opts.DeferManager = deferred.NewManager(deferred.Config{Enabled: true, Timeout: testwait.Deadline(time.Minute)})

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	childArrived, replyToChild := make(chan struct{}), make(chan struct{})
	finishChild := sync.OnceFunc(func() { close(replyToChild) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		switch id := canonicalID(ParseMCPFrame(payload).ID); id {
		case parentID:
			select {
			case <-childArrived:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			if _, err := io.WriteString(w, "data: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"reply\":\"parent POST\"}}\n\n"+
				"data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{\"data\":\"server event\"}}\n\n"); err != nil {
				t.Error(err)
			}
		case childID:
			close(childArrived)
			select {
			case <-replyToChild:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if _, err := io.WriteString(w, `{"jsonrpc":"2.0","id":2,"result":{"reply":"child POST"}}`); err != nil {
				t.Error(err)
			}
		default:
			t.Errorf("unexpected upstream ID %q", id)
		}
	}))
	defer upstream.Close()
	defer finishChild()
	in, feed := io.Pipe()
	defer func() { _ = in.Close(); _ = feed.Close() }()
	var out lockedHTTPBuffer
	done := make(chan error, 1)
	go func() { done <- RunHTTPProxy(ctx, in, &out, io.Discard, upstream.URL, nil, opts) }()

	parentMessage := strings.Replace(heldNativeCall, `"echo"`, `"send_tool"`, 1)
	childMessage := strings.Replace(parentMessage, `"id":1`, `"id":2`, 1)
	if _, err := io.WriteString(feed, parentMessage+"\n"+childMessage+"\n"); err != nil {
		t.Fatal(err)
	}
	testwait.For(t, 5*time.Second, func() bool { return opts.DeferManager.HeldCount() == 2 }, "parent and child holds")
	holds := opts.DeferManager.Snapshot()
	slices.SortFunc(holds, func(a, b deferred.HeldAction) int { return a.CascadeDepth - b.CascadeDepth })
	parent, child := holds[0].ActionID, holds[1].ActionID
	childDone := parkedV3Approval(t, ctx, opts.DeferManager, child)
	parentDone := make(chan error, 1)
	go func() { parentDone <- opts.DeferManager.Resolve(parent, config.ActionAllow, deferred.SourceOperator) }()
	if err := awaitHeldTest(t, parentDone); err != nil {
		t.Fatal(err)
	}
	finishChild()
	if result := awaitHeldTest(t, childDone); result.decision != config.ActionAllow || result.err != nil {
		t.Fatalf("child resolution = %+v", result)
	}
	if err := feed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitHeldTest(t, done); err != nil {
		t.Fatal(err)
	}

	if got := out.String(); strings.Contains(got, "parent POST") ||
		!strings.Contains(got, "child POST") || !strings.Contains(got, "server event") {
		t.Fatalf("downstream should have the child's own reply and server event, got %q", got)
	}
	var replyIntents int
	for _, action := range verifiedMCPV3RegressionActions(t, writer, writerOpts) {
		if action.EffectBoundary == mcpDownstreamDeliveryBoundary && action.Phase == "intent" && action.RequestID == childID {
			replyIntents++
			if action.ParentActionID != child {
				t.Fatalf("child reply parent = %q, want %q", action.ParentActionID, child)
			}
		}
	}
	if replyIntents != 1 {
		t.Fatalf("child reply intents = %d, want 1", replyIntents)
	}
}

func TestMCPV3POSTScopeDoesNotClaimReusedID(t *testing.T) {
	id := json.RawMessage("1")
	opts := MCPProxyOpts{v3Session: &mcpV3Session{pending: make(map[string]*mcpV3Exchange)}}
	tracker := NewRequestTracker()
	request := receipt.EmitOpts{RequestID: canonicalID(id)}
	original := &mcpV3Exchange{request: request}
	if err := opts.bindV3Send(original); err != nil {
		t.Fatal(err)
	}
	oldRegistration := tracker.trackOutcome(id, TrackedRequestOutcome{})
	stale := opts.withV3POST(original, oldRegistration)
	opts.unbindV3Send(original)
	tracker.removeOwnedOutcome(id, oldRegistration)
	replacement := &mcpV3Exchange{request: request}
	if err := opts.bindV3Send(replacement); err != nil {
		t.Fatal(err)
	}
	currentRegistration := tracker.trackOutcome(id, TrackedRequestOutcome{Method: methodToolsCall})

	if _, ok := stale.consumeMCPResponse(tracker, id); ok || stale.takeV3Send(id) != nil {
		t.Fatal("stale POST took a replacement registration or exchange")
	}
	changedRegistration := opts.withV3POST(replacement, oldRegistration)
	if _, ok := changedRegistration.consumeMCPResponse(tracker, id); ok {
		t.Fatal("response claimed an exchange using a different registration")
	}
	current := opts.withV3POST(replacement, currentRegistration)
	if got, ok := current.consumeMCPResponse(tracker, id); !ok || got.Method != methodToolsCall {
		t.Fatalf("current POST lost its tracked request: %+v, %t", got, ok)
	}
	if got := current.takeV3Send(id); got != replacement {
		t.Fatalf("current POST lost its exchange: %p", got)
	}
}

func TestMCPV3HeldPreIntentRefusalCorrectsAllow(t *testing.T) {
	for _, mode := range []string{"missing_session", "cancelled_approval"} {
		t.Run(mode, func(t *testing.T) {
			writer, writerOpts := openMCPV3RegressionWriter(t, deferred.SurfaceMCPStdio)
			opts := (MCPProxyOpts{Transport: deferred.SurfaceMCPStdio}).WithV3ReceiptWriter(writer)
			if mode == "cancelled_approval" {
				opts = opts.withV3Session()
			}
			manager := deferred.NewManager(deferred.Config{Enabled: true, Timeout: time.Minute})
			approval, cancel := context.WithCancel(t.Context())
			defer cancel()
			var admissionErr error
			held := v3ManagerAction(opts, "withheld", func(res deferred.Resolution, release deferred.Release) {
				if res.FinalDecision != config.ActionAllow {
					t.Errorf("unexpected resolution %+v", res)
					return
				}
				if mode == "cancelled_approval" {
					cancel()
				}
				id := json.RawMessage("1")
				var exchange *mcpV3Exchange
				exchange, admissionErr = opts.admitV3HeldSend(t.Context(), heldV3Evidence(res, id, opts), release)
				if exchange != nil || opts.pendingV3Send(id) != nil {
					t.Error("refused held send registered a reply owner")
				}
			})
			if err := manager.Hold(held); err != nil {
				t.Fatal(err)
			}
			applied, err := manager.ResolveApprovalResultContext(approval, held.DeferID, config.ActionAllow, deferred.SourceOperator)
			if err != nil || applied != config.ActionBlock || admissionErr == nil {
				t.Fatalf("resolve = %q, %v; admission = %v", applied, err, admissionErr)
			}
			if mode == "cancelled_approval" && !errors.Is(admissionErr, context.Canceled) {
				t.Fatalf("cancelled approval admission = %v", admissionErr)
			}
			assertHeldEvidence(t, verifiedMCPV3RegressionActions(t, writer, writerOpts), []heldEvidencePoint{
				holdPoint(held.ActionID, ""), resolutionPoint(held.ActionID, config.ActionAllow, false),
				resolutionPoint(held.ActionID, config.ActionBlock, true),
			})
		})
	}
}
