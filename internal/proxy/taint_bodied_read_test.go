// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestRequestHasBody(t *testing.T) {
	chunked := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("a"))
	chunked.ContentLength = -1
	chunked.TransferEncoding = []string{"chunked"}
	unknown := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("a"))
	unknown.ContentLength = -1
	unknownEmpty := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody)
	unknownEmpty.ContentLength = -1
	zeroWithTrailer := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody)
	zeroWithTrailer.Trailer = http.Header{"X-Exfil": nil}
	for _, tc := range []struct {
		name string
		r    *http.Request
		want bool
	}{
		{"nil", nil, false},
		{"no_body", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", http.NoBody), false},
		{"zero_length", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("")), false},
		{"sized_body", httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://x.example/", strings.NewReader("payload")), true},
		{"chunked", chunked, true},
		{"unknown_length_body", unknown, true},
		{"unknown_length_no_body", unknownEmpty, false},
		{"zero_length_with_trailer", zeroWithTrailer, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := requestHasBody(tc.r); got != tc.want {
				t.Fatalf("requestHasBody=%v want %v", got, tc.want)
			}
		})
	}
}

// After untrusted exposure, a read-shaped method that carries a body must get
// the same decision as POST on intercepted HTTPS, and must not reach upstream
// without approval. Bodyless reads keep proceeding.
func TestInterceptTaintBodiedReadMethodsMatchPublish(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions, "get"} {
		for _, body := range []bool{false, true} {
			name := method + map[bool]string{false: "_bodyless", true: "_bodied"}[body]
			t.Run(name, func(t *testing.T) {
				p, _, rec, target, ic := newTaintInterceptFixture(t, nil)
				observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
				var upstreamCalls int
				handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					upstreamCalls++
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
				}))
				var reqBody io.Reader = http.NoBody
				if body {
					reqBody = strings.NewReader("notes from the session")
				}
				req := httptest.NewRequestWithContext(t.Context(), method, target, reqBody)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if !body {
					if w.Code != http.StatusOK || upstreamCalls != 1 {
						t.Fatalf("bodyless %s status=%d calls=%d body=%s", method, w.Code, upstreamCalls, w.Body)
					}
					return
				}
				post := evaluateHTTPTaint(p.CurrentConfig(), rec, http.MethodPost, req.URL, true)
				if post.Result.Decision != session.PolicyAsk {
					t.Fatalf("POST decision=%+v, want ask", post.Result)
				}
				if w.Code != http.StatusForbidden || upstreamCalls != 0 || !strings.Contains(w.Body.String(), post.Result.Reason) {
					t.Fatalf("bodied %s status=%d calls=%d body=%s, want forbidden %s", method, w.Code, upstreamCalls, w.Body, post.Result.Reason)
				}
			})
		}
	}
}

func TestForwardTaintBodiedGETAsksLikePost(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	proxyAddr, p, cleanup := setupForwardProxyWithInstance(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Enabled = false
		cfg.SessionProfiling.Enabled = true
	})
	defer cleanup()
	installForwardTestDialer(p, upstream.Listener.Addr().String())
	rec := p.sessionMgrPtr.Load().GetOrCreate(ceeSessionKey(nil, "", "127.0.0.1", envelope.ActorAuthSelfDeclared))
	observeHTTPResponseTaint(rec, p.cfgPtr.Load(), "http://evil.example.com/source", "text/plain", "forward_response", false)
	client := forwardHTTPClient(t, proxyAddr)

	do := func(body io.Reader) int {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://evil.example.com/search", body)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		return resp.StatusCode
	}
	if status := do(http.NoBody); status != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("bodyless GET status=%d hits=%d", status, hits.Load())
	}
	if status := do(strings.NewReader("notes from the session")); status != http.StatusForbidden || hits.Load() != 1 {
		t.Fatalf("bodied GET status=%d hits=%d, want forbidden without upstream", status, hits.Load())
	}
}

func TestInterceptTaintBodiedExtensionMethodsAndTrailers(t *testing.T) {
	t.Run("bodied_extension_methods", func(t *testing.T) {
		for _, method := range []string{"SEARCH", "PROPFIND", "CUSTOM"} {
			t.Run(method, func(t *testing.T) {
				p, _, rec, target, ic := newTaintInterceptFixture(t, nil)
				observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
				var upstreamCalls int
				handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
					upstreamCalls++
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
				}))
				req := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader("exfiltrated payload"))
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, req)
				if w.Code != http.StatusForbidden || upstreamCalls != 0 {
					t.Fatalf("bodied %s status=%d calls=%d body=%s, want forbidden without upstream", method, w.Code, upstreamCalls, w.Body)
				}
			})
		}
	})

	t.Run("get_zero_length_with_trailer", func(t *testing.T) {
		p, _, rec, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
			cfg.RequestBodyScanning.Enabled = false
		})
		observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
		var upstreamCalls int
		handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			upstreamCalls++
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}))
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
		req.Trailer = http.Header{"X-Exfil": {"secret"}}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || upstreamCalls != 0 {
			t.Fatalf("trailer GET status=%d calls=%d body=%s, want forbidden without upstream", w.Code, upstreamCalls, w.Body)
		}
	})

	t.Run("get_unknown_length_empty_body_with_trailer_hostile", func(t *testing.T) {
		p, _, rec, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
			cfg.RequestBodyScanning.Enabled = false
		})
		observeHTTPResponseFindings(rec, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
		var upstreamCalls int
		handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
			upstreamCalls++
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
		}))
		// Models an HTTP/2 GET with unknown length, 0 DATA bytes, and a trailing
		// HEADERS frame: admitInterceptTaint drains 0 bytes and sets ContentLength=0
		// while Trailer remains populated. Must fail closed instead of downgrading
		// to ActionClassRead.
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, strings.NewReader(""))
		req.ContentLength = -1
		req.Trailer = http.Header{"X-Exfil": {"secret"}}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden || upstreamCalls != 0 {
			t.Fatalf("hostile trailer GET status=%d calls=%d body=%s, want forbidden without upstream", w.Code, upstreamCalls, w.Body)
		}
	})
}

func TestInterceptTaintBodiedGETHostileExactPermission(t *testing.T) {
	p, _, _, target, ic := newTaintInterceptFixture(t, nil)
	shared := &SessionState{}
	shared.BindTaskSubject("forward:agent-a")
	WithTaintRecorder(shared)(p)
	observeHTTPResponseFindings(shared, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	var upstreamCalls int
	handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	}))

	// Without an exact permission, a bodied GET fails closed under hostile taint.
	unapproved := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, strings.NewReader("approved notes"))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, unapproved)
	if w.Code != http.StatusForbidden || upstreamCalls != 0 || !strings.Contains(w.Body.String(), "task_approval_unavailable") {
		t.Fatalf("unapproved bodied GET status=%d calls=%d body=%s", w.Code, upstreamCalls, w.Body)
	}

	// Grant exact permission for this GET + body; the matching request succeeds.
	approvedReq := httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, strings.NewReader("approved notes"))
	responseencoding.RequestIdentity(approvedReq.Header)
	removeHopByHopHeaders(approvedReq.Header)
	stripInternalIdentity(approvedReq)
	applyFullResponsePolicy(approvedReq.Header, nil)
	action := forwardRequestTaskAction(approvedReq, []byte("approved notes"))
	if err := shared.installTaskPermission(shared.TaskSnapshot().CurrentTaskID, session.TaskPermission{
		Action:    action,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("installTaskPermission: %v", err)
	}
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, strings.NewReader("approved notes")))
	if w2.Code != http.StatusOK || upstreamCalls != 1 {
		t.Fatalf("approved bodied GET status=%d calls=%d body=%s", w2.Code, upstreamCalls, w2.Body)
	}

	// Altering the body invalidates the digest and blocks again.
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, strings.NewReader("different notes")))
	if w3.Code != http.StatusForbidden || upstreamCalls != 1 {
		t.Fatalf("modified bodied GET status=%d calls=%d body=%s", w3.Code, upstreamCalls, w3.Body)
	}
}

func TestRequestHasBodyHTTP2RealServer(t *testing.T) {
	for _, tc := range []struct {
		name          string
		body          string
		unknownLength bool
		withTrailer   bool
		want          bool
	}{
		{name: "bodyless_get", want: false},
		{name: "zero_length_get", body: "", want: false},
		{name: "sized_body_get", body: "payload", want: true},
		{name: "unknown_length_data_get", body: "payload", unknownLength: true, want: true},
		{name: "zero_length_trailer_get", withTrailer: true, want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got atomic.Bool
			var isHTTP2 atomic.Bool
			var declaredTrailer atomic.Bool
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				isHTTP2.Store(r.ProtoMajor == 2)
				_, declared := r.Trailer["X-Exfil"]
				declaredTrailer.Store(declared)
				got.Store(requestHasBody(r))
				_, _ = io.Copy(io.Discard, r.Body)
				w.WriteHeader(http.StatusOK)
			}))
			srv.EnableHTTP2 = true
			srv.StartTLS()
			defer srv.Close()

			client := srv.Client()
			client.Transport.(*http.Transport).ForceAttemptHTTP2 = true
			var body io.Reader
			if tc.body != "" {
				if tc.unknownLength {
					body = io.NopCloser(strings.NewReader(tc.body))
				} else {
					body = strings.NewReader(tc.body)
				}
			} else if tc.withTrailer {
				body = io.NopCloser(strings.NewReader(""))
			}
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/search", body)
			if err != nil {
				t.Fatal(err)
			}
			if tc.unknownLength {
				req.ContentLength = -1
			}
			if tc.withTrailer {
				req.ContentLength = 0
				req.Trailer = http.Header{"X-Exfil": nil}
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			_, _ = io.Copy(io.Discard, resp.Body)
			if !isHTTP2.Load() {
				t.Fatal("request did not negotiate HTTP/2")
			}
			if got.Load() != tc.want {
				t.Fatalf("HTTP/2 requestHasBody=%v, want %v", got.Load(), tc.want)
			}
			// The client sends a zero-length trailer request with unknown
			// length, so the result above alone could come from that branch.
			// Confirm the server saw the declared trailer; the known-zero
			// trailer branch is checked directly in TestRequestHasBody.
			if declaredTrailer.Load() != tc.withTrailer {
				t.Fatalf("server saw declared trailer=%v, want %v", declaredTrailer.Load(), tc.withTrailer)
			}
		})
	}
}

func TestCheckRedirect_BodiedGET307BlockedWhenTainted(t *testing.T) {
	p, cfg, sc := redirectPolicyTestProxy(t)
	cfg.Taint.Enabled = true
	cfg.Taint.Policy = config.ModeBalanced
	rec := &SessionState{}
	observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)

	makeHop := func(body string) *http.Request {
		var rdr io.Reader = http.NoBody
		if body != "" {
			rdr = strings.NewReader(body)
		}
		ctx := context.WithValue(t.Context(), ctxKeyClientIP, "127.0.0.1")
		ctx = context.WithValue(ctx, ctxKeyRequestID, "req-redirect-bodied-get")
		ctx = context.WithValue(ctx, ctxKeyAgent, agentAnonymous)
		ctx = context.WithValue(ctx, ctxKeyRedirectTransport, TransportForward)
		ctx = context.WithValue(ctx, ctxKeyRedirectSessionRecorder, rec)
		ctx = context.WithValue(ctx, ctxKeyAgentConfig, cfg)
		ctx = context.WithValue(ctx, ctxKeyAgentScanner, sc)
		req := httptest.NewRequestWithContext(ctx, http.MethodGet, "https://target.vendor.example/hop", rdr)
		if body != "" {
			req.GetBody = func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(body)), nil
			}
		}
		return req
	}
	orig := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://target.vendor.example/start", http.NoBody)

	if err := p.client.CheckRedirect(makeHop(""), []*http.Request{orig}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("bodyless 307 GET err = %v, want http.ErrUseLastResponse", err)
	}
	err := p.client.CheckRedirect(makeHop("redirected payload"), []*http.Request{orig})
	blockedErr, ok := blockedRequestErrorFrom(err)
	if !ok || blockedErr.layer != "taint_policy" {
		t.Fatalf("bodied 307 GET redirect err = %v, want taint_policy block", err)
	}
}

func TestReverseTaintBodiedReadAndExtensionMethodsBlocked(t *testing.T) {
	cfg := reverseParityBaseConfig(t)
	cfg.CrossRequestDetection.Enabled = false
	cfg.SessionProfiling.Enabled = true
	cfg.Taint.Enabled = true
	cfg.Taint.Policy = config.ModeBalanced

	var upstreamHits atomic.Int32
	rp, p, _ := newReverseParityHarness(t, cfg, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.WriteHeader(http.StatusOK)
	})
	rec := p.SessionMgrPtr().Load().GetOrCreate(responseTaintSessionKey(cfg, "", "192.0.2.1", envelope.ActorAuthSelfDeclared))
	observeHTTPResponseTaint(rec, cfg, "https://untrusted.vendor.example/page", "text/html", "forward_response", false)

	// Bodyless GET proceeds.
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://api.vendor.example/items", http.NoBody)
	req.RemoteAddr = "192.0.2.1:1234"
	w := httptest.NewRecorder()
	rp.ServeHTTP(w, req)
	if w.Code != http.StatusOK || upstreamHits.Load() != 1 {
		t.Fatalf("bodyless reverse GET status=%d hits=%d", w.Code, upstreamHits.Load())
	}

	// Bodied GET and bodied extension method SEARCH are blocked by taint.
	for _, method := range []string{http.MethodGet, "SEARCH"} {
		t.Run("bodied_"+method, func(t *testing.T) {
			before := upstreamHits.Load()
			r := httptest.NewRequestWithContext(t.Context(), method, "http://api.vendor.example/items", strings.NewReader("payload"))
			r.RemoteAddr = "192.0.2.1:1234"
			rw := httptest.NewRecorder()
			rp.ServeHTTP(rw, r)
			if rw.Code != http.StatusForbidden || upstreamHits.Load() != before {
				t.Fatalf("bodied reverse %s status=%d hits=%d (before=%d) body=%s", method, rw.Code, upstreamHits.Load(), before, rw.Body)
			}
			// The refusal must come from taint, not another request gate.
			want := evaluateHTTPTaint(cfg, rec, method, r.URL, true).Result.Reason
			if got := rw.Header().Get(blockreason.HeaderReason); got != string(blockreason.AuthorityMismatch) || want == "" || !strings.Contains(rw.Body.String(), want) {
				t.Fatalf("bodied reverse %s block reason=%q body=%q, want taint refusal %q", method, got, rw.Body, want)
			}
		})
	}
}

// Exposure recorded while a required intent receipt is written must be
// enforced before the forward request is sent, for POST and bodied reads
// alike. Intercept already re-checks after its receipt wait.
func TestForwardTaintRechecksExposureAfterRequiredReceipt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		expose bool
	}{
		{name: "post_unchanged", method: http.MethodPost},
		{name: "post_exposed_during_receipt", method: http.MethodPost, expose: true},
		{name: "bodied_get_exposed_during_receipt", method: http.MethodGet, expose: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _, _, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.RequestBodyScanning.Enabled = true
				cfg.FlightRecorder.RequireReceipts = true
				cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"93.184.216.34"}}
			})
			rec := &SessionState{}
			WithTaintRecorder(rec)(p)
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			intents := 0
			receipts.emitter = receipt.NewEmitter(receipt.EmitterConfig{
				Recorder: receipts.rec, PrivKey: receipts.priv,
				OnReceipt: func(rcpt *receipt.Receipt) {
					if rcpt.ActionRecord.DecisionPhase != receipt.DecisionPhaseIntent {
						return
					}
					intents++
					if tc.expose {
						observeHTTPResponseFindings(rec, p.CurrentConfig(), "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
					}
				},
			})
			p.receiptEmitterPtr.Store(receipts.emitter)
			var upstreamCalls atomic.Int32
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				upstreamCalls.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			})}
			target = strings.Replace(target, "https://", "http://", 1)
			req := httptest.NewRequestWithContext(t.Context(), tc.method, target, strings.NewReader("payload=1"))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			wantStatus, wantCalls := http.StatusOK, int32(1)
			if tc.expose {
				wantStatus, wantCalls = http.StatusForbidden, 0
			}
			if intents != 1 || w.Code != wantStatus || upstreamCalls.Load() != wantCalls {
				t.Fatalf("intents=%d status=%d calls=%d body=%s, want status %d calls %d", intents, w.Code, upstreamCalls.Load(), w.Body, wantStatus, wantCalls)
			}
			if tc.expose {
				// The signed refusal records the exposure that caused it,
				// not the clean admission-time state.
				var outcome *receipt.ActionRecord
				for _, rcpt := range receipts.findReceipts(t) {
					if rcpt.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome {
						ar := rcpt.ActionRecord
						outcome = &ar
					}
				}
				if outcome == nil || outcome.SessionTaintLevel != session.TaintExternalHostile.String() || outcome.TaintDecision != session.PolicyBlock.String() {
					t.Fatalf("refusal outcome does not record the live hostile state: %+v", outcome)
				}
			}
		})
	}
}

func TestTaskTaintRecheckReason(t *testing.T) {
	required := taintDecision{Result: session.PolicyDecisionResult{Decision: session.PolicyAsk, Reason: session.TaskPermissionRequired}}
	granted := taintDecision{Result: session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: session.TaskPermissionGranted}}
	approved := taintDecision{Result: session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: session.TaskApprovalGranted}}
	allowed := taintDecision{Result: session.PolicyDecisionResult{Decision: session.PolicyAllow}}
	for _, tc := range []struct {
		name         string
		admitted     taintDecision
		after        taintDecision
		reauthorized bool
		want         string
	}{
		{name: "expired_stored_grant", admitted: granted, after: required, want: session.TaskApprovalStale},
		{name: "expired_grant_after_broad_approval", admitted: granted, after: required, reauthorized: true, want: session.TaskApprovalStale},
		{name: "one_time_exact_approval_still_covers", admitted: approved, after: required, reauthorized: true, want: ""},
		{name: "new_requirement_after_clean_admission", admitted: allowed, after: required, want: session.TaskApprovalStale},
		{name: "grant_still_matches", admitted: granted, after: granted, want: ""},
		{name: "task_changed_after_approval", admitted: taintDecision{Result: approved.Result, Task: session.TaskContext{CurrentTaskID: "t1"}}, after: taintDecision{Result: allowed.Result, Task: session.TaskContext{CurrentTaskID: "t2"}}, reauthorized: true, want: session.TaskApprovalStale},
		{name: "new_ask_after_clean_admission", admitted: allowed, after: taintDecision{Result: session.PolicyDecisionResult{Decision: session.PolicyAsk, Reason: "external_publish_after_untrusted_external_exposure"}}, want: "external_publish_after_untrusted_external_exposure"},
		{name: "fresh_allow_survives_rotation", admitted: taintDecision{Result: allowed.Result, Task: session.TaskContext{CurrentTaskID: "t1"}}, after: taintDecision{Result: allowed.Result, Task: session.TaskContext{CurrentTaskID: "t2"}}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := taskTaintRecheckReason(tc.admitted, tc.after, tc.reauthorized); got != tc.want {
				t.Fatalf("reason=%q want %q", got, tc.want)
			}
		})
	}
}

// Exposure that arrives after a clean admission leaves the exact action
// unbound; the recheck binds it so a grant installed in advance still
// matches, and an unbuffered body stays refused.
func TestForwardPreSendTaintRecheckMatchesExistingGrant(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = true
	target := "http://upload.example/items"
	newReq := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader("payload=1"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	body := []byte("payload=1")
	for _, tc := range []struct {
		name       string
		grant      bool
		body       []byte
		wantReason string
	}{
		{name: "existing_grant_matches", grant: true, body: body, wantReason: ""},
		{name: "no_grant_refused", body: body, wantReason: session.TaskApprovalStale},
		{name: "unbuffered_body_refused", grant: true, body: nil, wantReason: session.TaskApprovalStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &SessionState{}
			rec.BeginNewTask("task")
			rec.BindTaskSubject("invocation")
			if tc.grant {
				if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, session.TaskPermission{Action: forwardRequestTaskAction(newReq(), body), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			admitted := evaluateHTTPTaskTaint(cfg, rec, http.MethodPost, newReq().URL, true, &forwardTaskAction{subject: "invocation"})
			observeHTTPResponseFindings(rec, cfg, "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			task := forwardTaskAction{subject: "invocation"}
			_, reason := forwardPreSendTaintRecheck(cfg, rec, newReq(), tc.body, &task, taintAdmission{decision: admitted})
			if reason != tc.wantReason {
				t.Fatalf("reason=%q want %q", reason, tc.wantReason)
			}
		})
	}
}

// The intercept recheck binds the exact action the same way when exposure
// arrives after a clean admission, so a grant installed in advance still
// matches and an unbuffered body stays refused.
func TestRecheckInterceptTaintMatchesExistingGrant(t *testing.T) {
	cfg := config.Defaults()
	cfg.Taint.Enabled = true
	target := "https://upload.example/items"
	newReq := func() *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader("payload=1"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	body := []byte("payload=1")
	for _, tc := range []struct {
		name       string
		grant      bool
		body       []byte
		wantReason string
	}{
		{name: "existing_grant_matches", grant: true, body: body, wantReason: ""},
		{name: "no_grant_refused", body: body, wantReason: session.TaskApprovalStale},
		{name: "unbuffered_body_refused", grant: true, body: nil, wantReason: session.TaskApprovalStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := &SessionState{}
			rec.BeginNewTask("task")
			rec.BindTaskSubject("invocation")
			if tc.grant {
				if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, session.TaskPermission{Action: forwardRequestTaskAction(newReq(), body), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			ic := &InterceptContext{taintConfig: cfg, taintRecorder: rec, taintTask: forwardTaskAction{subject: "invocation"}}
			ic.taint = evaluateHTTPTaskTaint(cfg, rec, http.MethodPost, newReq().URL, true, &ic.taintTask)
			if ic.taint.Result.Decision != session.PolicyAllow || ic.taintTask.action.Valid() {
				t.Fatalf("admission=%+v action bound=%v, want a clean allow with no bound action", ic.taint.Result, ic.taintTask.action.Valid())
			}
			observeHTTPResponseFindings(rec, cfg, "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			if reason := recheckInterceptTaint(ic, newReq(), tc.body); reason != tc.wantReason {
				t.Fatalf("reason=%q want %q", reason, tc.wantReason)
			}
		})
	}
}

// Envelope signing runs between task admission and the send, and can block
// while it buffers an unread body. Exposure recorded during signing is
// enforced before the request leaves, with or without required receipts.
func TestForwardTaintRechecksExposureDuringEnvelopeSigning(t *testing.T) {
	for _, required := range []bool{false, true} {
		t.Run(map[bool]string{false: "optional_receipts", true: "required_receipts"}[required], func(t *testing.T) {
			p, _, _, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.RequestBodyScanning.Enabled = false
				cfg.FlightRecorder.RequireReceipts = required
				cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"93.184.216.34"}}
			})
			rec := &SessionState{}
			WithTaintRecorder(rec)(p)
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(receipts.emitter)
			// The signature nonce is read inside envelope signing, after task
			// admission and before the send.
			nonce := &exposingBody{r: rand.Reader, expose: func() {
				observeHTTPResponseFindings(rec, p.CurrentConfig(), "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			}}
			signer, err := envelope.NewSigner(envelope.SignerConfig{PrivKey: receipts.priv, KeyID: "signing-test", SignedComponents: []string{"@method", "@target-uri"}, RandReader: nonce})
			if err != nil {
				t.Fatal(err)
			}
			p.envelopeEmitterPtr.Store(envelope.NewEmitter(envelope.EmitterConfig{Signer: signer}))
			var upstreamCalls atomic.Int32
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				upstreamCalls.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			})}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, strings.Replace(target, "https://", "http://", 1), strings.NewReader("payload=1"))
			req.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			if rec.RiskSnapshot().Level == session.TaintTrusted {
				t.Fatal("signing never ran, so the exposure hook did not fire")
			}
			if w.Code != http.StatusForbidden || upstreamCalls.Load() != 0 {
				t.Fatalf("bodied GET exposed during signing status=%d calls=%d body=%s", w.Code, upstreamCalls.Load(), w.Body)
			}
			var refusal *receipt.ActionRecord
			for _, rcpt := range receipts.findReceipts(t) {
				if rcpt.ActionRecord.Verdict == config.ActionBlock {
					ar := rcpt.ActionRecord
					refusal = &ar
				}
			}
			if refusal == nil || refusal.SessionTaintLevel != session.TaintExternalHostile.String() {
				t.Fatalf("refusal receipt does not record the live hostile state: %+v", refusal)
			}
		})
	}
}

// An exact grant is bound on the headers admission sees. Exposure that
// arrives while the envelope is signed must still match that grant, not a
// digest that includes the injected mediation headers. With request body
// scanning off, the body signing buffered is what the grant is matched on.
// The receipts then record the grant and the live exposure, not the clean
// admission.
func TestTaintLateExactGrantSurvivesEnvelopeInjection(t *testing.T) {
	grantFor := func(t *testing.T, rec *SessionState, method, target string, body []byte) {
		t.Helper()
		twin := httptest.NewRequestWithContext(t.Context(), method, target, strings.NewReader(string(body)))
		twin.Header.Set("Content-Type", "text/plain")
		stripInternalIdentity(twin)
		removeHopByHopHeaders(twin.Header)
		applyFullResponsePolicy(twin.Header, nil)
		responseencoding.RequestIdentity(twin.Header)
		if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, session.TaskPermission{Action: forwardRequestTaskAction(twin, body), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	exposingSigner := func(t *testing.T, receipts *receiptProxyHelper, expose func()) *envelope.Emitter {
		t.Helper()
		signer, err := envelope.NewSigner(envelope.SignerConfig{PrivKey: receipts.priv, KeyID: "signing-test", SignedComponents: []string{"@method", "@target-uri"}, RandReader: &exposingBody{r: rand.Reader, expose: expose}})
		if err != nil {
			t.Fatal(err)
		}
		return envelope.NewEmitter(envelope.EmitterConfig{Signer: signer})
	}
	// Every receipt written after the send must carry the grant that
	// released it and the hostile exposure that made the grant decisive.
	assertReleaseEvidence := func(t *testing.T, receipts *receiptProxyHelper) {
		t.Helper()
		found := receipts.findReceipts(t)
		if len(found) == 0 {
			t.Fatal("no receipts recorded")
		}
		last := found[len(found)-1].ActionRecord
		if last.TaintDecisionReason != session.TaskPermissionGranted || last.SessionTaintLevel != session.TaintExternalHostile.String() {
			t.Fatalf("terminal receipt taint reason=%q level=%q, want %q at %q", last.TaintDecisionReason, last.SessionTaintLevel, session.TaskPermissionGranted, session.TaintExternalHostile)
		}
	}
	body := []byte("payload=1")

	for _, scanning := range []bool{true, false} {
		name := map[bool]string{true: "body_scanning_on", false: "body_scanning_off"}[scanning]

		t.Run("forward/"+name, func(t *testing.T) {
			p, _, _, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.RequestBodyScanning.Enabled = scanning
				cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"93.184.216.34"}}
			})
			rec := &SessionState{}
			rec.BindTaskSubject("invocation")
			WithTaintRecorder(rec)(p)
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(receipts.emitter)
			target = strings.Replace(target, "https://", "http://", 1)
			grantFor(t, rec, http.MethodPost, target, body)
			exposed := false
			p.envelopeEmitterPtr.Store(exposingSigner(t, receipts, func() {
				exposed = true
				observeHTTPResponseFindings(rec, p.CurrentConfig(), "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			}))
			var upstreamCalls atomic.Int32
			var upstreamBody atomic.Value
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				upstreamCalls.Add(1)
				got, _ := io.ReadAll(r.Body)
				upstreamBody.Store(string(got))
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			})}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()
			p.handleForwardHTTP(w, req)
			if !exposed || w.Code != http.StatusOK || upstreamCalls.Load() != 1 {
				t.Fatalf("exposed=%v status=%d calls=%d body=%s, want the exact grant to admit the request", exposed, w.Code, upstreamCalls.Load(), w.Body)
			}
			if got := upstreamBody.Load(); got != string(body) {
				t.Fatalf("upstream received body %q, want the granted body %q", got, body)
			}
			assertReleaseEvidence(t, receipts)
		})

		t.Run("intercept/"+name, func(t *testing.T) {
			p, _, _, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = scanning
			})
			rec := &SessionState{}
			rec.BindTaskSubject("invocation")
			WithTaintRecorder(rec)(p)
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(receipts.emitter)
			grantFor(t, rec, http.MethodPost, target, body)
			exposed := false
			ic.EnvelopeEmitter = exposingSigner(t, receipts, func() {
				exposed = true
				observeHTTPResponseFindings(rec, ic.Config, "https://other.example/reference", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			})
			ic.EnvelopeEmitterSet = true
			var upstreamCalls int
			var upstreamBody string
			handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				upstreamCalls++
				if r.Body != nil {
					got, _ := io.ReadAll(r.Body)
					upstreamBody = string(got)
				}
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
			}))
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "text/plain")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if !exposed || w.Code != http.StatusOK || upstreamCalls != 1 {
				t.Fatalf("exposed=%v status=%d calls=%d body=%s, want the exact grant to admit the request", exposed, w.Code, upstreamCalls, w.Body)
			}
			if upstreamBody != string(body) {
				t.Fatalf("upstream received body %q, want the granted body %q", upstreamBody, body)
			}
			assertReleaseEvidence(t, receipts)
		})
	}
}

// retainedRequestBody only returns a complete replay copy within the bound;
// anything else leaves the body unbound so the binder keeps refusing it.
func TestRetainedRequestBody(t *testing.T) {
	withGetBody := func(body string, getBody func() (io.ReadCloser, error), contentLength int64) *http.Request {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://x.example/", strings.NewReader(body))
		r.GetBody = getBody
		r.ContentLength = contentLength
		return r
	}
	replay := func(s string) func() (io.ReadCloser, error) {
		return func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(s)), nil }
	}
	for _, tc := range []struct {
		name  string
		req   *http.Request
		limit int
		want  []byte
	}{
		{name: "complete_copy", req: withGetBody("payload", replay("payload"), 7), limit: 16, want: []byte("payload")},
		{name: "unknown_length_copy", req: withGetBody("payload", replay("payload"), -1), limit: 16, want: []byte("payload")},
		{name: "no_get_body", req: withGetBody("payload", nil, 7), limit: 16},
		{name: "over_limit", req: withGetBody("payload", replay("payload"), 7), limit: 4},
		{name: "get_body_error", req: withGetBody("payload", func() (io.ReadCloser, error) { return nil, errors.New("not replayable") }, 7), limit: 16},
		{name: "length_mismatch", req: withGetBody("payload", replay("pay"), 7), limit: 16},
		{name: "read_error_after_full_length", req: withGetBody("payload", func() (io.ReadCloser, error) {
			return io.NopCloser(io.MultiReader(strings.NewReader("payload"), iotest.ErrReader(errors.New("replay interrupted")))), nil
		}, 7), limit: 16},
		{name: "no_limit", req: withGetBody("payload", replay("payload"), 7), limit: 0},
		{name: "no_body", req: httptest.NewRequestWithContext(t.Context(), http.MethodPost, "http://x.example/", http.NoBody), limit: 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := retainedRequestBody(tc.req, tc.limit); !bytes.Equal(got, tc.want) || (got == nil) != (tc.want == nil) {
				t.Fatalf("retainedRequestBody=%q want %q", got, tc.want)
			}
		})
	}
}

// exposeOnRiskRead records hostile exposure just before the nth risk read,
// so a test can land exposure between two specific taint evaluations.
type exposeOnRiskRead struct {
	*SessionState
	reads  atomic.Int32
	nth    int32
	expose func()
}

func (e *exposeOnRiskRead) RiskSnapshot() session.SessionRisk {
	if e.reads.Add(1) == e.nth {
		e.expose()
	}
	return e.SessionState.RiskSnapshot()
}

// Exposure recorded after a clean admission but before the live task
// decision makes that decision the first to require permission. With body
// scanning off, the body must still be read so an existing exact grant
// matches instead of refusing an unbound action.
func TestForwardTaintLiveRequirementBindsFullBody(t *testing.T) {
	body := []byte("payload=1")
	p, _, _, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
		cfg.ForwardProxy.Enabled = true
		cfg.RequestBodyScanning.Enabled = false
		cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"93.184.216.34"}}
	})
	target = strings.Replace(target, "https://", "http://", 1)
	base := &SessionState{}
	base.BindTaskSubject("invocation")
	twin := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(string(body)))
	twin.Header.Set("Content-Type", "text/plain")
	stripInternalIdentity(twin)
	removeHopByHopHeaders(twin.Header)
	applyFullResponsePolicy(twin.Header, nil)
	responseencoding.RequestIdentity(twin.Header)
	if err := base.installTaskPermission(base.TaskSnapshot().CurrentTaskID, session.TaskPermission{Action: forwardRequestTaskAction(twin, body), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	rec := &exposeOnRiskRead{SessionState: base, nth: 2}
	rec.expose = func() {
		observeHTTPResponseFindings(base, p.CurrentConfig(), "http://untrusted.example/page", "text/html", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	}
	WithTaintRecorder(rec)(p)
	var upstreamCalls atomic.Int32
	var upstreamBody atomic.Value
	p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
		upstreamCalls.Add(1)
		got, _ := io.ReadAll(r.Body)
		upstreamBody.Store(string(got))
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	})}
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	p.handleForwardHTTP(w, req)
	if base.RiskSnapshot().Level != session.TaintExternalHostile {
		t.Fatalf("exposure hook did not fire (risk reads=%d)", rec.reads.Load())
	}
	if w.Code != http.StatusOK || upstreamCalls.Load() != 1 || upstreamBody.Load() != string(body) {
		t.Fatalf("status=%d calls=%d upstream body=%v body=%s, want the exact grant to admit the full body", w.Code, upstreamCalls.Load(), upstreamBody.Load(), w.Body)
	}
}

// exposeOnWriteFile records exposure on the nth write to a v3 receipt file,
// so exposure can land while a specific effect is being admitted.
type exposeOnWriteFile struct {
	*os.File
	writes int
	nth    int
	expose func()
}

func (f *exposeOnWriteFile) Write(data []byte) (int, error) {
	f.writes++
	if f.writes == f.nth {
		f.expose()
	}
	return f.File.Write(data)
}

// Exposure recorded while an intercepted request's upstream effect is
// admitted is caught by the post-admission recheck. With receipts optional
// and no intent written, that refusal still writes the ordinary signed taint
// denial, as the first recheck does.
func TestInterceptPostEffectRecheckRefusalWritesDenialReceipt(t *testing.T) {
	p, _, _, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = false
	})
	rec := &SessionState{}
	rec.BindTaskSubject("invocation")
	WithTaintRecorder(rec)(p)
	receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
	p.receiptEmitterPtr.Store(receipts.emitter)
	exposed := false
	keySeed := sha256.Sum256([]byte("post effect recheck fixture"))
	key := ed25519.NewKeyFromSeed(keySeed[:])
	first := true
	writer, err := v3.OpenStreamWriter(t.Context(), v3.StreamWriterOptions{
		Dir: t.TempDir(), SigningKey: key, PolicyHash: v3.Digest(nil),
		Identity: v3.Writer{Instance: "example", Product: "Pipelock", Version: "3"},
		Coverage: v3.Coverage{Surfaces: []string{transportInterceptReceipt}, RedactionRuleset: v3.Ruleset{ID: "example", Version: "1", Hash: v3.Digest(nil)}},
		// Write 1 is the opening record; write 2 is this request's effect
		// admission, after the first recheck has already passed.
		CreateTempFile: func(dir, pattern string) (v3.StreamFile, error) {
			file, err := os.CreateTemp(dir, pattern)
			if err != nil || !first {
				return file, err
			}
			first = false
			return &exposeOnWriteFile{File: file, nth: 2, expose: func() {
				exposed = true
				observeHTTPResponseFindings(rec, ic.Config, "https://other.example/reference", "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = writer.Close(ctx, nil)
	})
	WithV3ReceiptWriter(writer)(p)
	var upstreamCalls int
	handler := newInterceptHandler(ic, roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		upstreamCalls++
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok")), Request: r}, nil
	}))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader("payload=1"))
	req.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if !exposed || w.Code != http.StatusForbidden || upstreamCalls != 0 {
		t.Fatalf("exposed=%v status=%d calls=%d body=%s, want the post-admission recheck to refuse", exposed, w.Code, upstreamCalls, w.Body)
	}
	var denial *receipt.ActionRecord
	for _, rcpt := range receipts.findReceipts(t) {
		if rcpt.ActionRecord.Verdict == config.ActionBlock && rcpt.ActionRecord.Layer == "taint_policy" {
			ar := rcpt.ActionRecord
			denial = &ar
		}
	}
	if denial == nil || denial.SessionTaintLevel != session.TaintExternalHostile.String() {
		t.Fatalf("taint denial receipt missing or stale: %+v", denial)
	}
}
