// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/responseencoding"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const interceptTaintHost = "reference.vendor.example"

func newTaintInterceptFixture(t *testing.T, configure func(*config.Config)) (*Proxy, http.Handler, *SessionState, string, *InterceptContext) {
	t.Helper()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/message:send" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":{"token":"`+"AKIA"+"IOSFODNN7EXAMPLE"+`"}}`)
			return
		}
		_, _ = io.WriteString(w, "reference material")
	}))
	t.Cleanup(upstream.Close)
	cache, _, cfg, sc, logger, m := testInterceptSetup(t)
	cfg.SessionProfiling.Enabled = true
	cfg.AdaptiveEnforcement.Enabled = false
	if configure != nil {
		configure(cfg)
	}
	p, err := New(cfg, logger, sc, m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		t.Fatal(err)
	}
	rt := upstream.Client().Transport.(*http.Transport).Clone()
	rt.TLSClientConfig.ServerName = u.Hostname()
	rt.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	t.Cleanup(rt.CloseIdleConnections)
	u.Host = net.JoinHostPort(interceptTaintHost, port)
	ic := &InterceptContext{
		Config: cfg, Scanner: sc, Logger: logger, Metrics: m, CertCache: cache,
		Proxy: p, TargetHost: interceptTaintHost, TargetPort: port, ClientIP: testLoopbackIP,
	}
	rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(cfg, "", testLoopbackIP, ic.ActorAuth))
	return p, newInterceptHandler(ic, rt), rec, u.String(), ic
}

func TestInterceptTaintSharedRecorder(t *testing.T) {
	p, handler, ordinaryRec, target, _ := newTaintInterceptFixture(t, nil)
	shared := &SessionState{}
	WithTaintRecorder(shared)(p)
	if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body)
	}
	if shared.RiskSnapshot().Level != session.TaintExternalUntrusted || ordinaryRec.RiskSnapshot().Contaminated {
		t.Fatalf("shared=%+v ordinary=%+v", shared.RiskSnapshot(), ordinaryRec.RiskSnapshot())
	}
	if w := interceptTaintRequest(t, handler, http.MethodPost, target); w.Code != http.StatusForbidden {
		t.Fatalf("POST status=%d body=%s", w.Code, w.Body)
	}
}

func TestInterceptTaintTaskRotation(t *testing.T) {
	p, _, rec, target, ic := newTaintInterceptFixture(t, nil)
	ic.Recorder = rec
	observeHTTPResponseFindings(rec, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
	initInterceptTaint(ic, r)
	rec.BeginNewTask("rotated task")
	observeHTTPResponseFindings(rec, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	w := httptest.NewRecorder()
	if admitInterceptTaint(ic, w, r, audit.NewRequestLogContext("test"), "test-action", nil, nil) || w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), session.TaskApprovalStale) {
		t.Fatalf("rotated admission status=%d body=%s", w.Code, w.Body)
	}
	ic.taint.Result.Reason = session.TaskPermissionGranted
	if interceptTaskAdmissionCurrent(ic) {
		t.Fatal("missing task permission admitted after rotation")
	}
}

func interceptTaintRequest(t *testing.T, handler http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), method, target, nil))
	return w
}

func TestInterceptTaintResponseExposure(t *testing.T) {
	for _, allowlisted := range []bool{false, true} {
		t.Run(map[bool]string{false: "untrusted", true: "allowlisted"}[allowlisted], func(t *testing.T) {
			_, handler, rec, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				if allowlisted {
					cfg.Taint.AllowlistedDomains = []string{interceptTaintHost}
				}
			})
			if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
				t.Fatalf("GET status=%d body=%s", w.Code, w.Body)
			}
			want := session.TaintExternalUntrusted
			if allowlisted {
				want = session.TaintAllowlistedReference
			}
			if got := rec.RiskSnapshot(); got.Level != want || len(got.Sources) == 0 {
				t.Fatalf("intercepted response risk=%+v, want %s with source", got, want)
			}
		})
	}
}

func TestInterceptTaintPublishParity(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, "QUERY"} {
		t.Run(method, func(t *testing.T) {
			p, handler, rec, target, _ := newTaintInterceptFixture(t, nil)
			observeHTTPResponseTaint(rec, p.CurrentConfig(), target, "text/plain", "forward_response", false)
			u, err := url.Parse(target)
			if err != nil {
				t.Fatal(err)
			}
			want := evaluateHTTPTaint(p.CurrentConfig(), rec, method, u)
			if want.Result.Decision != session.PolicyAsk {
				t.Fatalf("plaintext decision=%+v, want ask", want.Result)
			}
			w := interceptTaintRequest(t, handler, method, target)
			if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), want.Result.Reason) {
				t.Fatalf("intercept %s status=%d body=%s, want forbidden %s", method, w.Code, w.Body, want.Result.Reason)
			}
		})
	}
}

func TestInterceptTaintGETThenPublish(t *testing.T) {
	for _, tc := range []struct {
		name, policy          string
		allowlisted, disabled bool
		wantStatus            int
		wantLevel             session.TaintLevel
	}{
		{name: "balanced", policy: config.ModeBalanced, wantStatus: http.StatusForbidden, wantLevel: session.TaintExternalUntrusted},
		{name: "strict", policy: config.ModeStrict, wantStatus: http.StatusForbidden, wantLevel: session.TaintExternalUntrusted},
		{name: "permissive", policy: config.ModePermissive, wantStatus: http.StatusOK, wantLevel: session.TaintExternalUntrusted},
		{name: "allowlisted", policy: config.ModeBalanced, allowlisted: true, wantStatus: http.StatusOK, wantLevel: session.TaintAllowlistedReference},
		{name: "disabled", disabled: true, wantStatus: http.StatusOK, wantLevel: session.TaintTrusted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, handler, rec, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.Taint.Policy = tc.policy
				cfg.Taint.Enabled = !tc.disabled
				if tc.allowlisted {
					cfg.Taint.AllowlistedDomains = []string{interceptTaintHost}
				}
			})
			if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
				t.Fatalf("GET status=%d body=%s", w.Code, w.Body)
			}
			if got := rec.RiskSnapshot().Level; got != tc.wantLevel {
				t.Fatalf("GET exposure=%s want=%s", got, tc.wantLevel)
			}
			if w := interceptTaintRequest(t, handler, http.MethodPost, target); w.Code != tc.wantStatus {
				t.Fatalf("POST status=%d body=%s", w.Code, w.Body)
			}
		})
	}
}

func TestInterceptTaintReloadPreservesExposure(t *testing.T) {
	p, handler, rec, target, _ := newTaintInterceptFixture(t, nil)
	observeHTTPResponseFindings(rec, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
	for _, policy := range []string{config.ModePermissive, config.ModeBalanced} {
		t.Run(policy, func(t *testing.T) {
			cfg := p.CurrentConfig().Clone()
			cfg.Taint.Policy = policy
			cfg.Taint.AllowlistedDomains = []string{interceptTaintHost}
			if !p.Reload(cfg, scanner.MustNew(cfg)) {
				t.Fatal("reload rejected")
			}
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(receipts.emitter)
			want := http.StatusForbidden
			if policy == config.ModePermissive {
				want = http.StatusOK
			}
			if w := interceptTaintRequest(t, handler, http.MethodPost, target); w.Code != want {
				t.Fatalf("POST after reload status=%d body=%s", w.Code, w.Body)
			}
			if got := rec.RiskSnapshot().Level; got != session.TaintExternalHostile {
				t.Fatalf("reload cleared hostile exposure: %s", got)
			}
			for _, emitted := range receipts.findReceipts(t) {
				if got := emitted.ActionRecord.PolicyHash; got != cfg.CanonicalPolicyHash() {
					t.Fatalf("reload receipt policy hash=%s want current=%s", got, cfg.CanonicalPolicyHash())
				}
			}
		})
	}
}

func TestInterceptTaintHostileResponseFindings(t *testing.T) {
	p, handler, rec, target, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
		cfg.ResponseScanning.Action = config.ActionWarn
		cfg.A2AScanning.Enabled = true
		cfg.A2AScanning.Action = config.ActionBlock
	})
	if w := interceptTaintRequest(t, handler, http.MethodGet, target+"/message:send"); w.Code != http.StatusForbidden {
		t.Fatalf("hostile GET status=%d body=%s", w.Code, w.Body)
	}
	if got := rec.RiskSnapshot(); got.Level != session.TaintExternalHostile || len(got.FindingKinds) == 0 {
		t.Fatalf("intercept response findings=%+v", got)
	}
	p.approver = nil
	if w := interceptTaintRequest(t, handler, http.MethodPost, target); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "task_approval_unavailable") {
		t.Fatalf("POST after hostile response status=%d body=%s", w.Code, w.Body)
	}
}

func TestInterceptTaintReloadAllowlist(t *testing.T) {
	p, handler, rec, target, _ := newTaintInterceptFixture(t, nil)
	cfg := p.CurrentConfig().Clone()
	cfg.Taint.AllowlistedDomains = []string{interceptTaintHost}
	if !p.Reload(cfg, scanner.MustNew(cfg)) {
		t.Fatal("reload rejected")
	}
	if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
		t.Fatalf("GET after reload status=%d body=%s", w.Code, w.Body)
	}
	if got := rec.RiskSnapshot().Level; got != session.TaintAllowlistedReference {
		t.Fatalf("GET after allowlist reload=%s", got)
	}
}

func TestInterceptTaintTaskPermissionAndReceipts(t *testing.T) {
	for _, granted := range []bool{false, true} {
		t.Run(map[bool]string{false: "unavailable", true: "exact_grant"}[granted], func(t *testing.T) {
			p, handler, _, target, ic := newTaintInterceptFixture(t, nil)
			ic.Agent, ic.ActorAuth = "bound-worker", envelope.ActorAuthBound
			rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth))
			observeHTTPResponseFindings(rec, ic.Config, target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			rec.BindTaskSubject("forward:" + ic.Agent)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, nil)
			responseencoding.RequestIdentity(req.Header)
			applyFullResponsePolicy(req.Header, nil)
			if granted {
				permission := session.TaskPermission{Action: forwardRequestTaskAction(req, nil), ExpiresAt: time.Now().Add(time.Hour)}
				if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, permission); err != nil {
					t.Fatal(err)
				}
			}
			receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
			p.receiptEmitterPtr.Store(receipts.emitter)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			wantStatus, wantReason, wantDecision := http.StatusForbidden, "task_approval_unavailable", config.ActionBlock
			if granted {
				wantStatus, wantReason, wantDecision = http.StatusOK, session.TaskPermissionGranted, config.ActionAllow
			}
			if w.Code != wantStatus {
				t.Fatalf("POST status=%d body=%s", w.Code, w.Body)
			}
			found := false
			for _, r := range receipts.findReceipts(t) {
				ar := r.ActionRecord
				if ar.Transport == "intercept" && ar.Method == http.MethodPost {
					found = true
					if ar.SessionTaintLevel != session.TaintExternalHostile.String() || !ar.SessionContaminated || ar.TaintDecisionReason != wantReason || ar.TaintDecision != wantDecision {
						t.Fatalf("receipt taint=%+v", ar)
					}
				}
			}
			if !found {
				t.Fatal("missing intercept receipt")
			}
		})
	}
}

func TestInterceptTaintTerminalApproval(t *testing.T) {
	for _, hostile := range []bool{false, true} {
		t.Run(map[bool]string{false: "untrusted", true: "hostile"}[hostile], func(t *testing.T) {
			p, handler, rec, target, _ := newTaintInterceptFixture(t, nil)
			var kinds []session.HostileFindingKind
			if hostile {
				kinds = []session.HostileFindingKind{session.FindingDLP}
			}
			observeHTTPResponseFindings(rec, p.CurrentConfig(), target, "text/plain", "forward_response", kinds)
			r, w := io.Pipe()
			t.Cleanup(func() { _ = r.Close(); _ = w.Close() })
			output := taskPromptWriter(func(prompt []byte) (int, error) {
				answer := "y\n"
				if _, text, found := strings.Cut(string(prompt), "enter y "); found {
					challenge, _, _ := strings.Cut(text, ".")
					answer = "y " + challenge + "\n"
				} else if !strings.Contains(string(prompt), "Allow (y)") {
					return len(prompt), nil
				}
				_, err := io.WriteString(w, answer)
				return len(prompt), err
			})
			p.approver = hitl.New(1, hitl.WithTerminal(true), hitl.WithInput(r), hitl.WithOutput(output))
			t.Cleanup(p.approver.Close)
			if response := interceptTaintRequest(t, handler, http.MethodPost, target); response.Code != http.StatusOK {
				t.Fatalf("approved POST status=%d body=%s", response.Code, response.Body)
			}
		})
	}
}

func TestInterceptTaintBodyBufferingWhenBodyScanningDisabled(t *testing.T) {
	const payload = `{"action":"publish","item":"report"}`
	for _, tc := range []struct {
		name         string
		body         string
		maxBodyBytes int
		grant        bool
		terminal     bool
		wantStatus   int
		wantSubstr   string
	}{
		{name: "exact_grant", body: payload, maxBodyBytes: 1024, grant: true, wantStatus: http.StatusOK},
		{name: "terminal_approval", body: payload, maxBodyBytes: 1024, terminal: true, wantStatus: http.StatusOK},
		{name: "oversized_refused", body: strings.Repeat("a", 64), maxBodyBytes: 16, terminal: true, wantStatus: http.StatusForbidden, wantSubstr: "task_action_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, handler, _, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = false
				cfg.RequestBodyScanning.MaxBodyBytes = tc.maxBodyBytes
			})
			ic.Agent, ic.ActorAuth = "bound-worker", envelope.ActorAuthBound
			rec := p.sessionMgrPtr.Load().GetOrCreate(responseTaintSessionKey(ic.Config, ic.Agent, ic.ClientIP, ic.ActorAuth))
			observeHTTPResponseFindings(rec, ic.Config, target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})
			rec.BindTaskSubject("forward:" + ic.Agent)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, target, bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			if tc.grant {
				actionReq := req.Clone(t.Context())
				responseencoding.RequestIdentity(actionReq.Header)
				applyFullResponsePolicy(actionReq.Header, nil)
				permission := session.TaskPermission{
					Action:    forwardRequestTaskAction(actionReq, []byte(tc.body)),
					ExpiresAt: time.Now().Add(time.Hour),
				}
				if err := rec.installTaskPermission(rec.TaskSnapshot().CurrentTaskID, permission); err != nil {
					t.Fatal(err)
				}
			}
			if tc.terminal {
				rPipe, wPipe := io.Pipe()
				t.Cleanup(func() { _ = rPipe.Close(); _ = wPipe.Close() })
				output := taskPromptWriter(func(prompt []byte) (int, error) {
					if _, text, found := strings.Cut(string(prompt), "enter y "); found {
						challenge, _, _ := strings.Cut(text, ".")
						_, err := io.WriteString(wPipe, "y "+challenge+"\n")
						return len(prompt), err
					}
					return len(prompt), nil
				})
				p.approver = hitl.New(1, hitl.WithTerminal(true), hitl.WithInput(rPipe), hitl.WithOutput(output))
				t.Cleanup(p.approver.Close)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantSubstr != "" && !strings.Contains(w.Body.String(), tc.wantSubstr) {
				t.Fatalf("body=%q missing %q", w.Body.String(), tc.wantSubstr)
			}
		})
	}
}

func TestInterceptTaintMixedPlaintextAndHTTPSParity(t *testing.T) {
	for _, direction := range []string{"plaintext_to_https", "https_to_plaintext"} {
		t.Run(direction, func(t *testing.T) {
			p, interceptHandler, _, httpsTarget, _ := newTaintInterceptFixture(t, func(cfg *config.Config) {
				cfg.ForwardProxy.Enabled = true
				cfg.DNS.HostOverrides = map[string][]string{interceptTaintHost: {"127.0.0.1"}}
				cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8"}
			})
			plainUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, "external plain content")
			}))
			t.Cleanup(plainUpstream.Close)
			plainURL, err := url.Parse(plainUpstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			plainURL.Host = net.JoinHostPort(interceptTaintHost, plainURL.Port())
			plainTarget := plainURL.String()
			p.client = &http.Client{Transport: forwardBoundaryRoundTripper(func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     http.Header{"Content-Type": {"text/plain"}},
					Body:       io.NopCloser(strings.NewReader("external plain content")),
					Request:    r,
				}, nil
			})}

			doPlain := func(method string) *httptest.ResponseRecorder {
				req := httptest.NewRequestWithContext(t.Context(), method, plainTarget, nil)
				req.RemoteAddr = net.JoinHostPort(testLoopbackIP, "43210")
				w := httptest.NewRecorder()
				p.handleForwardHTTP(w, req)
				return w
			}

			if direction == "plaintext_to_https" {
				if w := doPlain(http.MethodGet); w.Code != http.StatusOK {
					t.Fatalf("plaintext GET status=%d body=%s", w.Code, w.Body.String())
				}
				if w := interceptTaintRequest(t, interceptHandler, http.MethodPost, httpsTarget); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "external_publish_after_untrusted_external_exposure") {
					t.Fatalf("intercept POST after plaintext GET status=%d body=%s", w.Code, w.Body.String())
				}
				return
			}
			if w := interceptTaintRequest(t, interceptHandler, http.MethodGet, httpsTarget); w.Code != http.StatusOK {
				t.Fatalf("intercept GET status=%d body=%s", w.Code, w.Body.String())
			}
			if w := doPlain(http.MethodPost); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "external_publish_after_untrusted_external_exposure") {
				t.Fatalf("plaintext POST after intercept GET status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestInterceptTaintReceiptsVerifyChain(t *testing.T) {
	p, handler, _, target, _ := newTaintInterceptFixture(t, nil)
	receipts := newReceiptProxyHelperWithMetrics(t, p.metrics)
	receipts.emitSessionOpen(t)
	p.receiptEmitterPtr.Store(receipts.emitter)

	if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body.String())
	}
	if w := interceptTaintRequest(t, handler, http.MethodPost, target); w.Code != http.StatusForbidden {
		t.Fatalf("POST status=%d body=%s", w.Code, w.Body.String())
	}

	chain := receipts.findReceipts(t)
	if len(chain) < 2 {
		t.Fatalf("receipt count=%d, want >= 2", len(chain))
	}
	res := receipt.VerifyChain(chain, receipts.pubHex)
	if !res.Valid {
		t.Fatalf("receipt.VerifyChain failed: %s (broken at seq %d)", res.Error, res.BrokenAtSeq)
	}
}

func TestWithTaintRecorderTypedNilSafe(t *testing.T) {
	p, handler, ordinaryRec, target, _ := newTaintInterceptFixture(t, nil)
	WithTaintRecorder((*SessionState)(nil))(p)
	if p.taintRecorder != nil {
		t.Fatalf("typed-nil recorder was not normalized to nil: %#v", p.taintRecorder)
	}
	if w := interceptTaintRequest(t, handler, http.MethodGet, target); w.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", w.Code, w.Body)
	}
	if ordinaryRec.RiskSnapshot().Level != session.TaintExternalUntrusted {
		t.Fatalf("ordinary recorder risk=%+v, want external_untrusted", ordinaryRec.RiskSnapshot())
	}
}

func TestWebSocketRelayUsesSharedTaintRecorder(t *testing.T) {
	cfg := config.Defaults()
	cfg.SessionProfiling.Enabled = false
	cfg.Taint.Enabled = true
	p := &Proxy{}
	shared := &SessionState{}
	WithTaintRecorder(shared)(p)
	relay := &wsRelay{proxy: p, cfg: cfg, targetURL: "ws://" + interceptTaintHost + "/events"}
	if !relay.observeUpstreamResponseFindings([]session.HostileFindingKind{session.FindingDLP}) {
		t.Fatal("observeUpstreamResponseFindings unexpectedly refused")
	}
	if got := shared.RiskSnapshot(); got.Level != session.TaintExternalHostile || !got.Contaminated {
		t.Fatalf("shared websocket taint=%+v, want hostile", got)
	}
}

func TestInterceptTaintSharedRecorderDoesNotHijackTaskSubject(t *testing.T) {
	p, handler, _, target, ic := newTaintInterceptFixture(t, func(cfg *config.Config) {
		cfg.KillSwitch.APIToken = "test-operator-token-for-shared-recorder"
	})
	shared := &SessionState{}
	WithTaintRecorder(shared)(p)
	ic.Agent, ic.ActorAuth = "bound-worker", envelope.ActorAuthBound
	observeHTTPResponseFindings(shared, p.CurrentConfig(), target, "text/plain", "forward_response", []session.HostileFindingKind{session.FindingDLP})

	w := interceptTaintRequest(t, handler, http.MethodPost, target)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "task_approval_unavailable") {
		t.Fatalf("POST status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "/api/v1/sessions/{key}/task") {
		t.Fatalf("shared-recorder refusal advertised inert forward task grant route: %s", w.Body.String())
	}
	const mcpSubject = "mcp-stdio-shared"
	shared.BindTaskSubject(mcpSubject)
	action := session.TaskAction{Method: "tools/call", Destination: "fixture", Tool: "write_file", Digest: strings.Repeat("a", 64)}
	if err := shared.installTaskPermission(shared.TaskSnapshot().CurrentTaskID, session.TaskPermission{
		Action: action, ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("installTaskPermission: %v", err)
	}
	if _, _, matched := shared.TaskPolicySnapshot(mcpSubject, action); !matched {
		t.Fatal("shared recorder taskSubject was hijacked before MCP binding")
	}
}
