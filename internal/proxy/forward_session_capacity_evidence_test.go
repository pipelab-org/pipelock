// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// capacityEvidence is the client response and refusal evidence for one
// forward or CONNECT session-capacity site.
type capacityEvidence struct {
	status       int
	headers      http.Header
	body         string
	upstream     int32
	events       string
	blocked      []map[string]any
	blockMetrics string
	receipts     []receipt.Receipt
	counters     map[string]float64
}

func TestForwardSessionCapacityEvidence(t *testing.T) {
	reason := session.ErrCapacity.Error()
	cases := []struct {
		name          string
		drive         func(t *testing.T) capacityEvidence
		status        int
		body          string
		blockHeaders  bool
		parentReceipt bool
		transport     string
		method        string
		target        *regexp.Regexp
		events        string
		tunnels       float64
		requests      float64
		scannerHits   float64
		entropy       float64
	}{
		{
			name:         "connect_admission",
			drive:        driveConnectAdmissionCapacity,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			blockHeaders: true,
			transport:    TransportConnect,
			method:       http.MethodConnect,
			target:       regexp.MustCompile(`^https://127\.0\.0\.1:[0-9]+$`),
			events:       "blocked",
			tunnels:      1,
		},
		{
			name:         "connect_entropy_recorder",
			drive:        driveConnectEntropyRecorderCapacity,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			blockHeaders: true,
			transport:    TransportConnect,
			method:       http.MethodConnect,
			target:       regexp.MustCompile(`^https://127\.0\.0\.1:[0-9]+$`),
			events:       "blocked",
			tunnels:      1,
			entropy:      1,
		},
		{
			name:          "connect_intercept",
			drive:         driveConnectInterceptCapacity,
			status:        http.StatusOK,
			parentReceipt: true,
			transport:     TransportConnect,
			method:        http.MethodConnect,
			target:        regexp.MustCompile(`^https://127\.0\.0\.1:[0-9]+$`),
			events:        "anomaly,blocked",
			tunnels:       1,
		},
		{
			name:         "forward_recorder",
			drive:        driveForwardRecorderCapacity,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			blockHeaders: true,
			transport:    TransportForward,
			method:       http.MethodGet,
			target:       regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+$`),
			events:       "blocked",
			requests:     1,
			scannerHits:  1,
		},
		{
			name:         "forward_cee_recorder",
			drive:        driveForwardCEERecorderCapacity,
			status:       http.StatusServiceUnavailable,
			body:         reason + "\n",
			blockHeaders: true,
			transport:    TransportForward,
			method:       http.MethodGet,
			target:       regexp.MustCompile(`^http://127\.0\.0\.1:[0-9]+$`),
			events:       "blocked",
			requests:     1,
			scannerHits:  1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.drive(t)
			if got.status != tc.status || got.body != tc.body || got.upstream != 0 {
				t.Fatalf("response status=%d body=%q upstream=%d", got.status, got.body, got.upstream)
			}
			assertCapacityBlockHeaders(t, got, tc.blockHeaders, reason)
			if len(got.blocked) != 1 {
				t.Fatalf("blocked events=%d events=%s", len(got.blocked), got.events)
			}
			blocked := got.blocked[0]
			if blocked["event"] != "blocked" || blocked["scanner"] != sessionCapacityLayer || blocked["reason"] != reason {
				t.Fatalf("blocked event=%v", blocked)
			}
			if blocked["method"] != tc.method || blocked["agent"] != agentAnonymous || blocked["client_ip"] != airlockAdmissionClient || blocked["message"] != "request blocked" {
				t.Fatalf("blocked event=%v", blocked)
			}
			if _, ok := blocked["mitre_technique"]; ok {
				t.Fatalf("blocked event carries mitre_technique: %v", blocked)
			}
			switch tc.transport {
			case TransportConnect:
				if blocked["target"] != "[redacted-url]" {
					t.Fatalf("CONNECT blocked target=%v", blocked["target"])
				}
			default:
				if !strings.Contains(fmt.Sprint(blocked["url"]), "127.0.0.1") {
					t.Fatalf("forward blocked url=%v event=%v", blocked["url"], blocked)
				}
			}
			if _, ok := blocked["block_class"]; ok {
				t.Fatalf("blocked event carries block_class: %v", blocked)
			}
			if got.counters["pipelock_tunnels_total{result=blocked,agent=_default}"] != tc.tunnels ||
				got.counters["pipelock_requests_total{result=blocked,agent=_default}"] != tc.requests ||
				got.counters["pipelock_scanner_hits_total{scanner=session_capacity,agent=_default}"] != tc.scannerHits ||
				got.counters["pipelock_cross_request_entropy_exceeded_total"] != tc.entropy {
				t.Fatalf("counters=%v blockMetrics=%s", got.counters, got.blockMetrics)
			}
			blocks := blockReceipts(got.receipts)
			if len(blocks) != 1 {
				t.Fatalf("block receipts=%d all=%d events=%s", len(blocks), len(got.receipts), got.events)
			}
			rec := blocks[0].ActionRecord
			if rec.Layer != sessionCapacityLayer || rec.Pattern != reason || rec.Verdict != config.ActionBlock ||
				rec.ActionType != receipt.ActionRead || rec.Transport != tc.transport || rec.Method != tc.method ||
				rec.Actor != agentAnonymous || rec.Redaction != nil {
				t.Fatalf("receipt record=%+v", rec)
			}
			if tc.parentReceipt {
				if rec.ParentActionID == "" || rec.ParentActionID == rec.ActionID {
					t.Fatalf("intercept receipt parent=%q action=%q", rec.ParentActionID, rec.ActionID)
				}
			} else if rec.ParentActionID != "" {
				t.Fatalf("receipt parent=%q", rec.ParentActionID)
			}
			if tc.blockHeaders {
				if got.headers.Get(blockreason.HeaderRecordedReceipt) != rec.ActionID {
					t.Fatalf("recorded receipt header=%q action=%q", got.headers.Get(blockreason.HeaderRecordedReceipt), rec.ActionID)
				}
				if got.headers.Get(blockreason.HeaderRequestID) != rec.RequestID || rec.RequestID == "" {
					t.Fatalf("request id header=%q receipt=%q", got.headers.Get(blockreason.HeaderRequestID), rec.RequestID)
				}
			}
			if !blockReceiptsPresent(got.receipts) {
				t.Fatal("block receipt missing")
			}
			// Reuse the characterization helper's block-metric view. findReceipts
			// already closed the recorder, so the receipt half is checked above.
			if got.blockMetrics == "" && (tc.tunnels > 0 || tc.requests > 0) {
				t.Fatalf("auditBlockMetrics saw no block counter: %s", got.blockMetrics)
			}
			if rec.PolicyHash == "" || !tc.target.MatchString(rec.Target) || len(got.receipts) != 1 || got.events != tc.events {
				t.Fatalf("events=%q want %q receipts=%d target=%q policy=%q", got.events, tc.events, len(got.receipts), rec.Target, rec.PolicyHash)
			}
			wantMetrics := "pipelock_tunnels_total"
			if tc.requests > 0 {
				wantMetrics = "pipelock_requests_total"
			}
			if got.blockMetrics != wantMetrics {
				t.Fatalf("block metrics=%s want %s", got.blockMetrics, wantMetrics)
			}
		})
	}
}

func assertCapacityBlockHeaders(t *testing.T, got capacityEvidence, want bool, reason string) {
	t.Helper()
	h := got.headers
	if h == nil {
		h = http.Header{}
	}
	if !want {
		for _, key := range []string{blockreason.HeaderReason, blockreason.HeaderLayer, blockreason.HeaderSeverity, blockreason.HeaderRetry, blockreason.HeaderVersion, blockreason.HeaderRecordedReceipt} {
			if h.Get(key) != "" {
				t.Fatalf("response set %s=%q", key, h.Get(key))
			}
		}
		return
	}
	wantHeaders := map[string]string{
		blockreason.HeaderReason:   string(blockreason.DataBudget),
		blockreason.HeaderLayer:    sessionCapacityLayer,
		blockreason.HeaderSeverity: string(blockreason.SeverityWarn),
		blockreason.HeaderRetry:    string(blockreason.RetryPolicy),
		blockreason.HeaderVersion:  blockreason.SchemaVersion,
		"Content-Type":             "text/plain; charset=utf-8",
		"X-Content-Type-Options":   "nosniff",
		"Content-Length":           strconv.Itoa(len(reason) + 1),
	}
	for key, value := range wantHeaders {
		if h.Get(key) != value {
			t.Fatalf("%s=%q want %q headers=%v", key, h.Get(key), value, h)
		}
	}
	if h.Get(blockreason.HeaderReceipt) != "" {
		t.Fatalf("block-reason receipt header=%q", h.Get(blockreason.HeaderReceipt))
	}
	requestID := h.Get(blockreason.HeaderRequestID)
	if requestID == "" || h.Get(blockreason.HeaderOperator) != "pipelock explain event "+requestID {
		t.Fatalf("operator header=%q request=%q", h.Get(blockreason.HeaderOperator), requestID)
	}
}

func blockReceipts(receipts []receipt.Receipt) []receipt.Receipt {
	var out []receipt.Receipt
	for _, got := range receipts {
		if got.ActionRecord.Verdict == config.ActionBlock {
			out = append(out, got)
		}
	}
	return out
}

func blockReceiptsPresent(receipts []receipt.Receipt) bool {
	return len(blockReceipts(receipts)) > 0
}

type capacitySink struct {
	logs     *bytes.Buffer
	receipts *receiptProxyHelper
}

func attachCapacityEvidence(t *testing.T, proxy *Proxy) capacitySink {
	t.Helper()
	logs := &bytes.Buffer{}
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	proxy.logger = logger
	receipts := newReceiptProxyHelperWithMetrics(t, proxy.metrics)
	proxy.receiptEmitterPtr.Store(receipts.emitter)
	return capacitySink{logs: logs, receipts: receipts}
}

func (s capacitySink) evidence(t *testing.T, proxy *Proxy, status int, header http.Header, body string, upstream int32) capacityEvidence {
	t.Helper()
	copied := http.Header{}
	for key, values := range header {
		copied[key] = append([]string(nil), values...)
	}
	return capacityEvidence{
		status:       status,
		headers:      copied,
		body:         body,
		upstream:     upstream,
		events:       auditEventTypes(s.logs.String()),
		blocked:      blockedAuditEvents(s.logs.String()),
		blockMetrics: auditBlockMetrics(t, proxy.metrics),
		receipts:     s.receipts.findReceipts(t),
		counters:     capacityCounters(t, proxy.metrics),
	}
}

func blockedAuditEvents(logs string) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev["event"] == "blocked" {
			out = append(out, ev)
		}
	}
	return out
}

func capacityCounters(t *testing.T, m *metrics.Metrics) map[string]float64 {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]float64{}
	for _, family := range families {
		name := family.GetName()
		for _, metric := range family.GetMetric() {
			key := name
			switch name {
			case "pipelock_tunnels_total", "pipelock_requests_total":
				if !metricHasLabel(metric, "result", "blocked") || !metricHasLabel(metric, "agent", "_default") {
					continue
				}
				key += "{result=blocked,agent=_default}"
			case "pipelock_scanner_hits_total":
				if !metricHasLabel(metric, "scanner", sessionCapacityLayer) || !metricHasLabel(metric, "agent", "_default") {
					continue
				}
				key += "{scanner=session_capacity,agent=_default}"
			case "pipelock_cross_request_entropy_exceeded_total":
			default:
				continue
			}
			out[key] += metricValue(metric)
		}
	}
	return out
}

func pinCapacitySession(t *testing.T, sm *SessionManager) {
	t.Helper()
	other := sm.GetOrCreate("other-quarantined-client")
	if other == nil {
		t.Fatal("capacity fixture could not admit the held session")
	}
	_, _, _ = other.AirlockForScope("").SetTier(config.AirlockTierDrain)
}

func capacityRequest(t *testing.T, method, target string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	req.RemoteAddr = airlockAdmissionClient + ":12345"
	return req
}

func driveConnectAdmissionCapacity(t *testing.T) capacityEvidence {
	t.Helper()
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 1
	cfg.ForwardProxy.SNIVerification = ptrBool(false)
	var calls atomic.Int32
	_, proxy, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	sink := attachCapacityEvidence(t, proxy)
	pinCapacitySession(t, proxy.sessionMgrPtr.Load())
	req := capacityRequest(t, http.MethodConnect, "http://proxy.example/")
	req.Host = upstream.Host
	w := httptest.NewRecorder()
	proxy.handleConnect(w, req)
	return sink.evidence(t, proxy, w.Code, w.Header(), w.Body.String(), calls.Load())
}

func driveConnectEntropyRecorderCapacity(t *testing.T) capacityEvidence {
	t.Helper()
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 1
	cfg.ForwardProxy.SNIVerification = ptrBool(false)
	cfg.CrossRequestDetection.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.Enabled = true
	cfg.CrossRequestDetection.EntropyBudget.BitsPerWindow = 1
	cfg.CrossRequestDetection.EntropyBudget.Action = config.ActionWarn
	var calls atomic.Int32
	_, proxy, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	sink := attachCapacityEvidence(t, proxy)
	key := CeeSessionKey(agentAnonymous, airlockAdmissionClient)
	tracker := proxy.entropyTrackerPtr.Load()
	tracker.Record(testCEEIdentity(key), []byte("abc123"))
	if !tracker.BudgetExceeded(testCEEIdentity(key)) {
		t.Fatal("fixture did not exhaust entropy")
	}
	var reached atomic.Bool
	proxy.connectCEEReady = func() {
		reached.Store(true)
		pinCapacitySession(t, proxy.sessionMgrPtr.Load())
	}
	req := capacityRequest(t, http.MethodConnect, "http://proxy.example/")
	req.Host = upstream.Host
	w := httptest.NewRecorder()
	proxy.handleConnect(w, req)
	if !reached.Load() {
		t.Fatal("CONNECT did not reach the entropy recorder check")
	}
	return sink.evidence(t, proxy, w.Code, w.Header(), w.Body.String(), calls.Load())
}

func driveForwardRecorderCapacity(t *testing.T) capacityEvidence {
	t.Helper()
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.Enabled = false
	cfg.SessionProfiling.MaxSessions = 1
	var calls atomic.Int32
	_, proxy, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	sink := attachCapacityEvidence(t, proxy)
	sm := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, proxy.metrics)
	t.Cleanup(sm.Close)
	proxy.sessionMgrPtr.Store(sm)
	pinCapacitySession(t, sm)
	req := capacityRequest(t, http.MethodGet, upstream.String()+"/control")
	w := httptest.NewRecorder()
	proxy.handleForwardHTTP(w, req)
	return sink.evidence(t, proxy, w.Code, w.Header(), w.Body.String(), calls.Load())
}

func driveForwardCEERecorderCapacity(t *testing.T) capacityEvidence {
	t.Helper()
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 1
	cfg.CrossRequestDetection.Enabled = true
	var calls atomic.Int32
	_, proxy, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	sink := attachCapacityEvidence(t, proxy)
	var reached atomic.Bool
	proxy.ceeAdmissionLocked = func() {
		if !reached.CompareAndSwap(false, true) {
			return
		}
		full := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, proxy.metrics)
		pinCapacitySession(t, full)
		proxy.sessionMgrPtr.Store(full)
	}
	req := capacityRequest(t, http.MethodGet, upstream.String()+"/control")
	w := httptest.NewRecorder()
	proxy.handleForwardHTTP(w, req)
	if !reached.Load() {
		t.Fatal("forward request did not reach CEE admission")
	}
	return sink.evidence(t, proxy, w.Code, w.Header(), w.Body.String(), calls.Load())
}

func driveConnectInterceptCapacity(t *testing.T) capacityEvidence {
	t.Helper()
	cfg := airlockAdmissionConfig(t, config.AirlockTierNone)
	cfg.SessionProfiling.MaxSessions = 1
	cfg.ForwardProxy.SNIVerification = ptrBool(false)
	cfg.TLSInterception.Enabled = true
	var calls atomic.Int32
	_, proxy, upstream := newReverseParityHarness(t, cfg, func(http.ResponseWriter, *http.Request) { calls.Add(1) })
	cache, _, _, _, _, _ := testInterceptSetup(t)
	proxy.certCachePtr.Store(cache)
	sink := attachCapacityEvidence(t, proxy)
	done := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(done)
		r.RemoteAddr = airlockAdmissionClient + ":12345"
		proxy.handleConnect(lateConnectHijacker{ResponseWriter: w, afterHijack: func() {
			full := NewSessionManager(&cfg.SessionProfiling, &cfg.AdaptiveEnforcement, proxy.metrics)
			pinCapacitySession(t, full)
			proxy.sessionMgrPtr.Store(full)
		}}, r)
	}))
	t.Cleanup(server.Close)
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstream.Host, upstream.Host); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not finish")
	}
	return sink.evidence(t, proxy, resp.StatusCode, resp.Header, string(body), calls.Load())
}
