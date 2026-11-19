// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestNativeCapacityHTTPAdmission(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		stallBody bool
	}{
		{name: "fetch", transport: TransportFetch},
		{name: "forward", transport: TransportForward},
		{name: "reverse_headers", transport: TransportReverse},
		{name: "reverse_body", transport: TransportReverse, stallBody: true},
		{name: "intercept", transport: "intercept"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const grace = 150 * time.Millisecond
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, configureNativeWarningFixtures)
			p.shutdownGrace = grace
			headers := nativeWarningFixtures(t, p, e)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			entered := make(chan struct{}, 2)
			upstreamCanceled := make(chan struct{}, 2)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.stallBody {
					w.Header().Set("Content-Type", "text/plain")
					_, _ = io.WriteString(w, "partial")
					if err := http.NewResponseController(w).Flush(); err != nil {
						return
					}
				}
				entered <- struct{}{}
				<-r.Context().Done()
				upstreamCanceled <- struct{}{}
			}))
			defer upstream.Close()
			dst, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			dst.Host = "api.vendor.example:" + dst.Port()
			handler := p.Handler()
			target := dst.String()
			switch tc.transport {
			case TransportFetch:
				target = "/fetch?url=" + url.QueryEscape(target)
			case TransportReverse:
				rp := NewReverseProxy(dst, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetSafeDialer(p.SafeDialer())
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				handler = rp
				target = "/"
			case "intercept":
				intercept := &InterceptContext{
					TargetHost: dst.Hostname(), TargetPort: dst.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(intercept, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					out := req.Clone(req.Context())
					out.URL.Scheme = "http"
					out.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
					return upstream.Client().Transport.RoundTrip(out)
				}))
			}
			request := func() *httptest.ResponseRecorder {
				w := httptest.NewRecorder()
				req := httptest.NewRequestWithContext(ctx, http.MethodGet, target, nil)
				req.Header = headers.Clone()
				handler.ServeHTTP(w, req)
				return w
			}
			done := make(chan *httptest.ResponseRecorder, 1)
			joined := make(chan struct{})
			go func() {
				defer close(joined)
				done <- request()
			}()
			defer func() {
				cancel()
				<-joined
			}()
			select {
			case <-entered:
			case early := <-done:
				t.Fatalf("admitted request ended before upstream effect: %d %s", early.Code, early.Body.String())
			case <-ctx.Done():
				t.Fatal("admitted request did not reach upstream")
			}
			const drainLimit = 2 * time.Second
			stoppedAt := time.Now()
			refused := request()
			if refused.Code != http.StatusServiceUnavailable || !strings.Contains(refused.Body.String(), ael.ErrCapacity.Error()) {
				t.Fatalf("second request = %d %s", refused.Code, refused.Body.String())
			}
			select {
			case <-entered:
				t.Fatal("refused request reached upstream")
			default:
			}
			drain, cancelDrain := context.WithDeadline(ctx, stoppedAt.Add(drainLimit))
			defer cancelDrain()
			select {
			case <-upstreamCanceled:
			case <-drain.Done():
				t.Fatal("upstream did not observe capacity cancellation")
			}
			waitCapacityDrain(t, drain, e)
			select {
			case <-done:
			case <-drain.Done():
				t.Fatal("admitted handler did not return after capacity stop")
			}
			drainTime := time.Since(stoppedAt)
			if drainTime > drainLimit {
				t.Fatalf("capacity drained in %s, limit %s", drainTime, drainLimit)
			}
			records := verifyNativeCapacityClose(t, e, dir)
			if want := receipt.DLPWarningSlots + 2; records != want {
				t.Fatalf("%s: wrote %d native records, want %d", tc.name, records, want)
			}
			assertNativeRecordBudget(t, tc.name, records, nativeRequestRecords)
			entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
			if err != nil {
				t.Fatal(err)
			}
			outcomes := 0
			individual, overflow := 0, 0
			for _, entry := range entries.Entries {
				signed, err := receipt.Unmarshal(entry.RawDetail)
				if err != nil {
					t.Fatal(err)
				}
				record := signed.ActionRecord
				if record.DecisionPhase == receipt.DecisionPhaseOutcome {
					outcomes++
					if tc.transport == TransportReverse && !strings.Contains(record.Pattern, "reason="+nativeCapacityStopReason) {
						t.Errorf("reverse cutoff outcome = %q", record.Pattern)
					}
				}
				if strings.HasPrefix(record.Pattern, nativeFixtureWarningPrefix) {
					individual++
				}
				if strings.Contains(record.Pattern, "additional warnings by pattern:") {
					overflow++
				}
			}
			if outcomes != 1 {
				t.Fatalf("signed outcome receipts = %d, want 1", outcomes)
			}
			if individual != receipt.DLPWarningSlots-1 || overflow != 1 {
				t.Fatalf("warning receipts = %d individual and %d overflow", individual, overflow)
			}
			t.Logf("stalled upstream canceled and native stream sealed with %d outcome; stop to drain %s", outcomes, drainTime)
		})
	}
}

func TestNativeCapacityReservesEachCredentialAudienceAllow(t *testing.T) {
	const (
		host       = "api.vendor.example"
		allowCount = nativeRequestRecords + 1
	)
	for _, tc := range []struct {
		name       string
		slots      int64
		wantStatus int
		wantAllows int
	}{
		{"admitted", nativeRequestRecords + allowCount, http.StatusOK, allowCount},
		{"refused", nativeRequestRecords + allowCount - 4, http.StatusServiceUnavailable, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, emitter, dir := newNativeCapacityProxy(t, tc.slots, func(cfg *config.Config) {
				cfg.ResponseScanning.Enabled = false
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.SensitiveHeaders = []string{headerNameAuthorization}
				for i := range allowCount {
					pattern := audienceReceiptTestPattern(host)
					pattern.Name = fmt.Sprintf("Test audience %03d", i)
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
				}
			})
			var hits atomic.Int32
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = io.WriteString(w, "ok")
			}))
			defer upstream.Close()

			endpoint, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			target := *endpoint
			target.Host = net.JoinHostPort(host, target.Port())
			p.client.Transport = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				out := req.Clone(req.Context())
				out.URL.Host = endpoint.Host
				return upstream.Client().Transport.RoundTrip(out)
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url="+url.QueryEscape(target.String()), nil)
			req.Header.Set(headerNameAuthorization, "Bearer "+audienceReceiptTestCredential)
			res := httptest.NewRecorder()
			p.handleFetch(res, req)
			if res.Code != tc.wantStatus {
				t.Fatalf("fetch status = %d, want %d, response %s", res.Code, tc.wantStatus, res.Body)
			}
			if tc.wantStatus == http.StatusServiceUnavailable {
				if !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) || hits.Load() != 0 {
					t.Fatalf("capacity refusal: body %s and %d upstream hits", res.Body, hits.Load())
				}
			} else {
				if hits.Load() != 1 {
					t.Fatalf("upstream hits = %d, want 1", hits.Load())
				}
				if _, err := emitter.ReserveNativeRecords(int(tc.slots)); !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("force the next admission to stop: %v", err)
				}
			}
			records := verifyNativeCapacityClose(t, emitter, dir)
			assertNativeRecordBudget(t, "fetch excluding audience batch", records-tc.wantAllows, nativeRequestRecords)
			rows, err := recorder.QuerySession(dir, emitter.Session(), &recorder.QueryFilter{Type: "action_receipt"})
			if err != nil {
				t.Fatal(err)
			}
			patterns := make(map[string]struct{})
			var signedCount int
			for _, row := range rows.Entries {
				signed, err := receipt.Unmarshal(row.RawDetail)
				if err != nil {
					t.Fatal(err)
				}
				if signed.ActionRecord.Layer != credentialAudienceReceiptExtensionKey {
					continue
				}
				if err := receipt.VerifyWithKey(signed, emitter.SignerKeyHex()); err != nil {
					t.Fatal(err)
				}
				signedCount++
				patterns[signed.ActionRecord.Pattern] = struct{}{}
			}
			if signedCount != tc.wantAllows || len(patterns) != tc.wantAllows {
				t.Fatalf("signed allows = %d, distinct patterns = %d, want %d", signedCount, len(patterns), tc.wantAllows)
			}
			assertNativeRecordBudget(t, "credential-audience batch", signedCount, allowCount)
			t.Logf("HTTP %d, upstream hits %d, verified individual allows %d", res.Code, hits.Load(), signedCount)
		})
	}
}

func TestNativeCapacityRefusesAuthorizationAtProxyBoundaries(t *testing.T) {
	const (
		host          = "api.vendor.example"
		intercepted   = "intercept"
		headerCarrier = "header"
		urlCarrier    = "url"
		bodyCarrier   = "body"
	)
	var hits atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	endpoint, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	destination := *endpoint
	destination.Host = net.JoinHostPort(host, endpoint.Port())

	for _, tc := range []struct{ transport, carrier string }{
		{TransportConnect, headerCarrier},
		{TransportFetch, urlCarrier},
		{TransportForward, headerCarrier},
		{TransportForward, urlCarrier},
		{TransportForward, bodyCarrier},
		{TransportReverse, headerCarrier},
		{TransportReverse, urlCarrier},
		{TransportReverse, bodyCarrier},
		{intercepted, headerCarrier},
		{intercepted, urlCarrier},
		{intercepted, bodyCarrier},
		{TransportWS, headerCarrier},
		{TransportWS, urlCarrier},
	} {
		t.Run(tc.transport+"/"+tc.carrier, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, func(cfg *config.Config) {
				cfg.RequestBodyScanning.Enabled = true
				cfg.RequestBodyScanning.ScanHeaders = true
				cfg.RequestBodyScanning.HeaderMode = config.HeaderModeSensitive
				cfg.RequestBodyScanning.SensitiveHeaders = []string{headerNameAuthorization}
				for i := range 16 {
					pattern := audienceReceiptTestPattern(host)
					pattern.Name = fmt.Sprintf("Test gateway %02d", i)
					cfg.DLP.Patterns = append(cfg.DLP.Patterns, pattern)
				}
			})
			outbound := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				out := req.Clone(req.Context())
				out.URL.Host = endpoint.Host
				return upstream.Client().Transport.RoundTrip(out)
			})
			p.client.Transport = outbound
			target := destination
			method := http.MethodGet
			var body io.Reader
			switch tc.carrier {
			case urlCarrier:
				target.RawQuery = url.Values{"fixture": []string{audienceReceiptTestCredential}}.Encode()
			case bodyCarrier:
				method = http.MethodPost
				body = strings.NewReader(fmt.Sprintf(`{"fixture":%q}`, audienceReceiptTestCredential))
			}

			var handler http.Handler = http.HandlerFunc(p.handleForwardHTTP)
			requestURL := target.String()
			switch tc.transport {
			case TransportConnect:
				handler = http.HandlerFunc(p.handleConnect)
				method = http.MethodConnect
				requestURL = target.Host
			case TransportFetch:
				handler = http.HandlerFunc(p.handleFetch)
				requestURL = "/fetch?url=" + url.QueryEscape(target.String())
			case TransportReverse:
				rp := NewReverseProxy(&destination, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				rp.SetSafeDialer(p.SafeDialer())
				handler = rp
				requestURL = "/"
				if target.RawQuery != "" {
					requestURL += "?" + target.RawQuery
				}
			case intercepted:
				ic := &InterceptContext{
					TargetHost: target.Hostname(), TargetPort: target.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(ic, outbound)
			case TransportWS:
				handler = http.HandlerFunc(p.handleWebSocket)
				target.Scheme = "wss"
				requestURL = "/ws?url=" + url.QueryEscape(target.String())
			}
			req := httptest.NewRequestWithContext(t.Context(), method, requestURL, body)
			if tc.carrier == headerCarrier {
				req.Header.Set(headerNameAuthorization, "Bearer "+audienceReceiptTestCredential)
			}
			if tc.carrier == bodyCarrier {
				req.Header.Set("Content-Type", "application/json")
			}
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) {
				t.Fatalf("capacity refusal = %d %s", res.Code, res.Body)
			}
			if hits.Load() != 0 {
				t.Fatalf("refused work reached upstream %d times", hits.Load())
			}
			verifyNativeCapacityClose(t, e, dir)
		})
	}
}

func TestNativeCapacityIssuerCookieBatch(t *testing.T) {
	const count = nativeRequestRecords + 1
	for _, admitted := range []bool{true, false} {
		t.Run(fmt.Sprintf("admitted=%t", admitted), func(t *testing.T) {
			slots := int64(nativeRequestRecords + 4)
			if admitted {
				slots += count
			}
			p, e, dir := newNativeCapacityProxy(t, slots)
			admission, err := p.reserveReceiptAdmission()
			if err != nil {
				t.Fatal(err)
			}
			defer admission.ReleaseNativeAdmission()
			ic := &InterceptContext{Proxy: p, Config: p.CurrentConfig(), receiptShard: admission}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://api.vendor.example/", nil)
			allowances := []issuerCookieAllowance{
				{Name: "first", Patterns: make([]string, count-1)},
				{Name: "last", Patterns: []string{"last pattern"}},
			}
			for i := range allowances[0].Patterns {
				allowances[0].Patterns[i] = fmt.Sprintf("fixture pattern %d", i)
			}
			err = ic.recordIssuerCookieAllows(audit.NewRequestLogContext("fixture"), req, req.URL.String(), allowances)
			want := count
			if !admitted {
				want = 0
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("issuer-cookie batch admission = %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				_, err = e.ReserveNativeRecords(int(slots))
				if !errors.Is(err, ael.ErrCapacity) {
					t.Fatalf("new admission = %v", err)
				}
			}
			admission.ReleaseNativeAdmission()
			records := verifyNativeCapacityClose(t, e, dir)
			if records != want {
				t.Fatalf("issuer-cookie batch: wrote %d native records, want %d", records, want)
			}
			assertNativeRecordBudget(t, "issuer-cookie batch", records, count)
		})
	}
}

const nativeFixtureWarningPrefix = "fixture advisory "

func configureNativeWarningFixtures(cfg *config.Config) {
	cfg.RequestBodyScanning.Enabled = true
	cfg.RequestBodyScanning.ScanHeaders = true
	cfg.RequestBodyScanning.SensitiveHeaders = nil
	for i := range receipt.DLPWarningSlots {
		cfg.RequestBodyScanning.SensitiveHeaders = append(cfg.RequestBodyScanning.SensitiveHeaders, fmt.Sprintf("X-Fixture-%02d", i))
		cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
			Name: fmt.Sprintf("%s%02d", nativeFixtureWarningPrefix, i), Regex: fmt.Sprintf("FIXTURE-ADVISORY-%02d", i),
			Severity: config.SeverityLow, Action: config.ActionWarn,
		})
	}
}

func nativeWarningFixtures(t *testing.T, p *Proxy, e *receipt.Emitter) http.Header {
	t.Helper()
	p.ScannerPtr().Load().SetDLPWarnHook(func(ctx context.Context, name, severity string) {
		receipt.EmitDLPWarning(ctx, e, receipt.EmitOpts{
			ActionID: receipt.NewActionID(), Target: "fixture", Transport: "fixture",
			Verdict: config.ActionWarn, Layer: "dlp", Pattern: name, Severity: severity,
		}, func(err error) { t.Errorf("emit native warning: %v", err) })
	})
	h := make(http.Header)
	for i := range receipt.DLPWarningSlots {
		h.Set(fmt.Sprintf("X-Fixture-%02d", i), fmt.Sprintf("FIXTURE-ADVISORY-%02d", i))
	}
	return h
}

func assertNativeRecordBudget(t *testing.T, unit string, records, reserved int) {
	t.Helper()
	if records > reserved {
		t.Fatalf("%s: wrote %d native records, reserved %d", unit, records, reserved)
	}
	t.Logf("%s: wrote %d native records, reserved %d", unit, records, reserved)
}

func newNativeCapacityProxy(t *testing.T, slots int64, configure ...func(*config.Config)) (*Proxy, *receipt.Emitter, string) {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{"api.vendor.example": {"127.0.0.1"}}
	cfg.TrustedDomains = []string{"api.vendor.example"}
	cfg.FetchProxy.Monitoring.EntropyThreshold = 0
	cfg.ForwardProxy.Enabled = true
	cfg.WebSocketProxy.Enabled = true
	cfg.FlightRecorder.RequireReceipts = true
	for _, apply := range configure {
		apply(cfg)
	}
	sc, err := scanner.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	rec, err := recorder.New(recorder.Config{Enabled: true, Dir: dir}, nil, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rec.Close() })
	session, err := recorder.AcquireRunSession(rec, recorder.DefaultSessionBase)
	if err != nil {
		t.Fatal(err)
	}
	slot := ael.ActivityRecordLimit(len(receipt.ActionUnclassified), 36)
	e := receipt.NewEmitter(receipt.EmitterConfig{Recorder: rec, PrivKey: key, Session: session, ConfigHash: coverageTestConfigHash, NativeCapacity: ael.NewCapacity(slots*slot + 2048)})
	if err := e.EmitSessionOpen(); err != nil {
		t.Fatal(err)
	}
	p, err := New(cfg, audit.NewNop(), sc, metrics.New(), WithRecorder(rec), WithReceiptEmitter(e), WithSession(session))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	return p, e, dir
}

func verifyNativeCapacityClose(t *testing.T, e *receipt.Emitter, dir string) int {
	t.Helper()
	select {
	case <-e.NativeCapacity().Drained():
	default:
		t.Fatal("native capacity leases still outstanding")
	}
	if err := e.EmitSessionClose("graceful_shutdown"); err != nil && !errors.Is(err, receipt.ErrChainSealed) {
		t.Fatal(err)
	}
	runs, err := filepath.Glob(filepath.Join(dir, "ael", "*"))
	if err != nil || len(runs) != 1 {
		t.Fatalf("native evidence paths %v, error %v", runs, err)
	}
	head, err := ael.VerifyRun(dir, filepath.Base(runs[0]), e.SignerKeyHex())
	if err != nil {
		t.Fatalf("verify native close: %v", err)
	}
	if head.RecordCount <= math.MaxInt {
		return int(head.RecordCount) - 2 // Open and close are outside the unit.
	}
	t.Fatalf("unexpected native record count %d", head.RecordCount)
	return 0
}

func TestNativeCapacityClosesWebSocket(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(nativeReceiptModeName(required), func(t *testing.T) {
			testNativeCapacityClosesWebSocket(t, required)
		})
	}
}

func testNativeCapacityClosesWebSocket(t *testing.T, required bool) {
	t.Helper()
	const frameWarningPrefix = "fixture frame advisory "
	const frameFinding = "fixture response advisory"
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+2*nativeWSMessageRecords+4, configureNativeWarningFixtures, func(cfg *config.Config) {
		cfg.FlightRecorder.RequireReceipts = required
		cfg.ResponseScanning.Enabled = true
		cfg.ResponseScanning.Action = config.ActionWarn
		cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: frameFinding, Regex: frameFinding})
		for i := range receipt.DLPWarningSlots {
			cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
				Name: fmt.Sprintf("%s%02d", frameWarningPrefix, i), Regex: fmt.Sprintf("FIXTURE-FRAME-%02d", i),
				Severity: config.SeverityLow, Action: config.ActionWarn,
			})
		}
	})
	headers := nativeWarningFixtures(t, p, e)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		if _, _, err := wsutil.ReadClientData(conn); err != nil {
			return
		}
		if err := wsutil.WriteServerMessage(conn, ws.OpText, []byte(frameFinding)); err != nil {
			return
		}
		_, _, _ = wsutil.ReadClientData(conn)
	}))
	defer upstream.Close()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	proxyServer := httptest.NewServer(p.Handler())
	defer proxyServer.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var markers []string
	for _, values := range headers {
		markers = append(markers, values...)
	}
	slices.Sort(markers)
	target := "ws://api.vendor.example:" + port + "/" + strings.Join(markers, "/")
	conn, _, _, err := (ws.Dialer{}).Dial(ctx, "ws"+strings.TrimPrefix(proxyServer.URL, "http")+"/ws?url="+url.QueryEscape(target))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	var frameParts []string
	for i := range receipt.DLPWarningSlots {
		frameParts = append(frameParts, fmt.Sprintf("FIXTURE-FRAME-%02d", i))
	}
	payload := []byte(strings.Join(frameParts, " "))
	if err := wsutil.WriteClientMessage(conn, ws.OpText, payload); err != nil {
		t.Fatal(err)
	}
	got, _, err := wsutil.ReadServerData(conn)
	if err != nil || string(got) != frameFinding {
		t.Fatalf("upstream echo = %q, %v", got, err)
	}
	assertCapacityRefusesFetch(t, p, ctx)
	_, _, err = wsutil.ReadServerData(conn)
	var closed wsutil.ClosedError
	if !errors.As(err, &closed) || closed.Code != ws.StatusGoingAway || closed.Reason != nativeCapacityStopReason {
		t.Fatalf("WebSocket terminal frame = %v", err)
	}
	waitCapacityDrain(t, ctx, e)
	records := verifyNativeCapacityClose(t, e, dir)
	rows, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	frameWarnings, frameFindings := 0, 0
	for _, row := range rows.Entries {
		signed, err := receipt.Unmarshal(row.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		switch pattern := signed.ActionRecord.Pattern; {
		case strings.Contains(pattern, frameWarningPrefix):
			frameWarnings++
		case pattern == frameFinding:
			frameFindings++
		}
	}
	if frameWarnings != receipt.DLPWarningSlots {
		t.Fatalf("WebSocket message warning receipts = %d, want %d", frameWarnings, receipt.DLPWarningSlots)
	}
	wantFindings := 0
	if required {
		wantFindings = 1
	}
	if frameFindings != wantFindings {
		t.Fatalf("WebSocket message finding receipts = %d, want %d", frameFindings, wantFindings)
	}
	assertNativeRecordBudget(t, "WebSocket client message", frameWarnings, nativeWSMessageRecords)
	assertNativeRecordBudget(t, "WebSocket upstream message", frameFindings, nativeWSMessageRecords)
	connectionRecords := records - frameWarnings - frameFindings
	wantConnection := receipt.DLPWarningSlots + 1
	if required {
		wantConnection++
	}
	if connectionRecords != wantConnection {
		t.Fatalf("WebSocket connection: wrote %d native records, want %d", connectionRecords, wantConnection)
	}
	assertNativeRecordBudget(t, "WebSocket connection", connectionRecords, nativeRequestRecords)
	verifyNativeStreamOutcome(t, e, dir, TransportWS, required)
}

func TestNativeCapacityRefusesUnreservedWebSocketMessages(t *testing.T) {
	for _, direction := range []string{"client", "upstream"} {
		t.Run(direction, func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			begin := make(chan struct{})
			upResult := make(chan error, 1)
			payload := []byte("fixture message")
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				up, _, _, err := ws.UpgradeHTTP(r, w)
				if err != nil {
					upResult <- err
					return
				}
				defer func() { _ = up.Close() }()
				if direction == "upstream" {
					select {
					case <-begin:
					case <-ctx.Done():
						return
					}
					if err := wsutil.WriteServerMessage(up, ws.OpText, payload); err != nil {
						upResult <- err
						return
					}
				}
				_, _, err = wsutil.ReadClientData(up)
				upResult <- err
			}))
			defer upstream.Close()
			defer cancel()
			_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(p.Handler())
			defer server.Close()
			target := "ws://api.vendor.example:" + port + "/"
			conn, _, _, err := (ws.Dialer{}).Dial(ctx, "ws"+strings.TrimPrefix(server.URL, "http")+"/ws?url="+url.QueryEscape(target))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = conn.Close() }()
			deadline, _ := ctx.Deadline()
			if err := conn.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			close(begin)
			if direction == "client" {
				if err := wsutil.WriteClientMessage(conn, ws.OpText, payload); err != nil {
					t.Fatal(err)
				}
			}
			_, _, err = wsutil.ReadServerData(conn)
			var closed wsutil.ClosedError
			if !errors.As(err, &closed) || closed.Code != ws.StatusGoingAway || closed.Reason != nativeCapacityStopReason {
				t.Fatalf("message refusal = %v", err)
			}
			select {
			case err := <-upResult:
				if !errors.As(err, &closed) {
					t.Fatalf("upstream received data or missed the close: %v", err)
				}
			case <-ctx.Done():
				t.Fatal("upstream did not settle")
			}
			waitCapacityDrain(t, ctx, e)
			verifyNativeCapacityClose(t, e, dir)
			verifyNativeStreamOutcome(t, e, dir, TransportWS, true)
		})
	}
}

func TestNativeCapacityClosesConnectTunnel(t *testing.T) {
	for _, required := range []bool{true, false} {
		t.Run(nativeReceiptModeName(required), func(t *testing.T) {
			testNativeCapacityClosesConnectTunnel(t, required)
		})
	}
}

func testNativeCapacityClosesConnectTunnel(t *testing.T, required bool) {
	t.Helper()
	p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+4, configureNativeWarningFixtures, func(cfg *config.Config) { cfg.FlightRecorder.RequireReceipts = required })
	headers := nativeWarningFixtures(t, p, e)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	upstream := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			upstream <- err
			return
		}
		defer func() { _ = conn.Close() }()
		_, err = io.Copy(conn, conn)
		upstream <- err
	}()
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(p.Handler())
	defer server.Close()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	target := "api.vendor.example:" + port
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	if err := headers.Write(conn); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT response = %v, %v", resp, err)
	}
	defer func() { _ = resp.Body.Close() }()
	const payload = "tunnel message"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil || string(got) != payload {
		t.Fatalf("upstream echo = %q, %v", got, err)
	}
	assertCapacityRefusesFetch(t, p, ctx)
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("expected CONNECT client socket to close, got %v", err)
	}
	select {
	case err := <-upstream:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("CONNECT upstream was not closed")
	}
	waitCapacityDrain(t, ctx, e)
	records := verifyNativeCapacityClose(t, e, dir)
	if want := receipt.DLPWarningSlots + 2; records != want {
		t.Fatalf("CONNECT: wrote %d native records, want %d", records, want)
	}
	assertNativeRecordBudget(t, "CONNECT outer", records, nativeRequestRecords)
	verifyNativeStreamOutcome(t, e, dir, TransportConnect, required)
}

func assertCapacityRefusesFetch(t *testing.T, p *Proxy, ctx context.Context) {
	t.Helper()
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url=https://api.vendor.example/", nil))
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), ael.ErrCapacity.Error()) {
		t.Fatalf("capacity refusal = %d %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct {
		method  string
		target  string
		handler http.HandlerFunc
	}{
		{http.MethodConnect, "api.vendor.example:443", p.handleConnect},
		{http.MethodGet, "/ws?url=wss://api.vendor.example/", p.handleWebSocket},
	} {
		res := httptest.NewRecorder()
		tc.handler(res, httptest.NewRequestWithContext(ctx, tc.method, tc.target, nil))
		if res.Code != http.StatusServiceUnavailable || !strings.Contains(res.Body.String(), ael.ErrCapacity.Error()) {
			t.Fatalf("%s %s capacity refusal = %d %s", tc.method, tc.target, res.Code, res.Body.String())
		}
	}
}

func waitCapacityDrain(t *testing.T, ctx context.Context, e *receipt.Emitter) {
	t.Helper()
	select {
	case <-e.NativeCapacity().Drained():
	case <-ctx.Done():
		t.Fatal("capacity did not drain")
	}
}

func verifyNativeStreamOutcome(t *testing.T, e *receipt.Emitter, dir, transport string, required bool) {
	t.Helper()
	result, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		record := signed.ActionRecord
		if record.Transport != transport || !strings.Contains(record.Pattern, nativeCapacityStopReason) {
			continue
		}
		if required && record.DecisionPhase != receipt.DecisionPhaseOutcome {
			continue
		}
		if !required && (record.DecisionPhase != "" || record.Layer != nativeStreamCloseLayer || record.Verdict != config.ActionWarn) {
			continue
		}
		if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("missing signed %s capacity outcome", transport)
}

func nativeReceiptModeName(required bool) string {
	if required {
		return "required"
	}
	return "best_effort"
}

func TestNativeCapacityClosesHTTPSSE(t *testing.T) {
	const intercepted = "intercept"
	const eventFinding = "fixture stream advisory"
	for _, tc := range []struct {
		transport string
		required  bool
	}{
		{TransportForward, true},
		{TransportForward, false},
		{TransportReverse, true},
		{TransportReverse, false},
		{intercepted, true},
		{intercepted, false},
	} {
		transport := tc.transport
		t.Run(transport+"/"+nativeReceiptModeName(tc.required), func(t *testing.T) {
			p, e, dir := newNativeCapacityProxy(t, nativeRequestRecords+nativeSSEFindingRecords+4, func(cfg *config.Config) {
				cfg.FlightRecorder.RequireReceipts = tc.required
				cfg.ResponseScanning.Enabled = true
				cfg.ResponseScanning.Action = config.ActionWarn
				cfg.ResponseScanning.SSEStreaming.Enabled = true
				cfg.ResponseScanning.SSEStreaming.Action = config.ActionWarn
				cfg.ResponseScanning.Patterns = append(cfg.ResponseScanning.Patterns, config.ResponseScanPattern{Name: eventFinding, Regex: eventFinding})
			})
			p.shutdownGrace = 150 * time.Millisecond
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			upstreamClosed := make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "data: {\"message\":%q}\n\n", eventFinding)
				if err := http.NewResponseController(w).Flush(); err != nil {
					return
				}
				<-r.Context().Done()
				close(upstreamClosed)
			}))
			defer upstream.Close()
			defer cancel()
			dst, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			dst.Host = "api.vendor.example:" + dst.Port()
			handler := p.Handler()
			switch transport {
			case TransportReverse:
				rp := NewReverseProxy(dst, p.ConfigPtr(), p.ScannerPtr(), p.logger, p.metrics, p.ks, nil, nil)
				rp.SetOwnerProxy(p)
				rp.SetSafeDialer(p.SafeDialer())
				rp.SetReceiptEmitter(p.ReceiptEmitterPtr())
				handler = rp
			case "intercept":
				intercept := &InterceptContext{
					TargetHost: dst.Hostname(), TargetPort: dst.Port(), Config: p.CurrentConfig(),
					Scanner: p.ScannerPtr().Load(), Logger: p.logger, Metrics: p.metrics, Proxy: p,
				}
				handler = newInterceptHandler(intercept, roundTripperFunc(func(req *http.Request) (*http.Response, error) {
					out := req.Clone(req.Context())
					out.URL.Scheme = "http"
					out.URL.Host = strings.TrimPrefix(upstream.URL, "http://")
					return upstream.Client().Transport.RoundTrip(out)
				}))
			}
			server := httptest.NewServer(handler)
			defer server.Close()
			defer cancel()
			client := server.Client()
			target := server.URL + "/"
			if transport == TransportForward {
				proxyURL, err := url.Parse(server.URL)
				if err != nil {
					t.Fatal(err)
				}
				rt := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
				defer rt.CloseIdleConnections()
				client = &http.Client{Transport: rt}
				target = dst.String()
			}
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
			if err != nil {
				t.Fatal(err)
			}
			if transport == "intercept" {
				request.Host = dst.Host
			}
			response, err := client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = response.Body.Close() }()
			reader := bufio.NewReader(response.Body)
			if event, err := reader.ReadString('\n'); err != nil || response.StatusCode != http.StatusOK || !strings.Contains(event, "fixture") {
				t.Fatalf("first SSE event: status=%d event=%q err=%v", response.StatusCode, event, err)
			}
			assertCapacityRefusesFetch(t, p, ctx)
			select {
			case <-upstreamClosed:
			case <-ctx.Done():
				t.Fatal("capacity did not close upstream SSE")
			}
			if rest, _ := io.ReadAll(reader); strings.Contains(string(rest), "data:") {
				t.Fatalf("unexpected event after capacity: %q", rest)
			}
			waitCapacityDrain(t, ctx, e)
			records := verifyNativeCapacityClose(t, e, dir)
			rows, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
			if err != nil {
				t.Fatal(err)
			}
			eventRecords := 0
			for _, row := range rows.Entries {
				signed, err := receipt.Unmarshal(row.RawDetail)
				if err != nil {
					t.Fatal(err)
				}
				if signed.ActionRecord.Layer == LayerSSEStream && strings.Contains(signed.ActionRecord.Pattern, eventFinding) {
					eventRecords++
				}
			}
			wantEventRecords := 0
			if tc.required {
				wantEventRecords = 1
			}
			if eventRecords != wantEventRecords {
				t.Fatalf("%s SSE event: wrote %d native records, want %d", transport, eventRecords, wantEventRecords)
			}
			assertNativeRecordBudget(t, transport+" SSE event", eventRecords, nativeSSEFindingRecords)
			assertNativeRecordBudget(t, transport+" SSE subscription", records-eventRecords, nativeRequestRecords)
			verifyNativeStreamOutcome(t, e, dir, transport, tc.required)
		})
	}
}
