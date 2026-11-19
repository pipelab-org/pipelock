// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"
	wsio "github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

type settlementTransport uint8

const (
	settlementStdio settlementTransport = iota
	settlementBridgeJSON
	settlementBridgeSSE
	settlementWebSocket
	settlementListenerJSON
	settlementListenerSSE
	settlementListenerGET
	settlementTransportCount
)

var settlementTransports = [settlementTransportCount]string{
	settlementStdio:        "stdio_subprocess",
	settlementBridgeJSON:   "stdio_http",
	settlementBridgeSSE:    "http_bridge_sse",
	settlementWebSocket:    "stdio_websocket",
	settlementListenerJSON: "http_listener",
	settlementListenerSSE:  "http_listener_sse",
	settlementListenerGET:  "http_listener_get",
}

type settlementFault uint8

const (
	settlementSuccess settlementFault = iota
	settlementDial
	settlementWriteUpstream
	settlementReadEmpty
	settlementReadPartial
	settlementReadSSE
	settlementScanError
	settlementTimeout
	settlementWriteClient
	settlementClientCancel
	settlementRequestCancel
	settlementIntentAppend
	settlementOutcomeAppend
	settlementShutdown
	settlementDuplicate
	settlementFaultCount
)

var settlementFaults = [settlementFaultCount]string{
	settlementSuccess:       "success",
	settlementDial:          "upstream_connect",
	settlementWriteUpstream: "upstream_write",
	settlementReadEmpty:     "upstream_read_before_byte",
	settlementReadPartial:   "upstream_read_mid_body",
	settlementReadSSE:       "upstream_read_mid_event",
	settlementScanError:     "response_scan_error",
	settlementTimeout:       "response_timeout",
	settlementWriteClient:   "downstream_write",
	settlementClientCancel:  "client_cancel",
	settlementRequestCancel: "request_context_cancel",
	settlementIntentAppend:  "intent_append",
	settlementOutcomeAppend: "outcome_append",
	settlementShutdown:      "shutdown_in_flight",
	settlementDuplicate:     "concurrent_duplicate_id",
}

type settlementCell struct {
	transport settlementTransport
	fault     settlementFault
	required  bool
	deferred  bool
}

func (c settlementCell) listener() bool { return c.transport >= settlementListenerJSON }

func (c settlementCell) subprocessStartFailure() bool {
	return c.transport == settlementStdio && c.fault == settlementDial
}

func (c settlementCell) bridge() bool {
	return c.transport == settlementBridgeJSON || c.transport == settlementBridgeSSE
}

func (c settlementCell) sse() bool {
	return c.transport == settlementBridgeSSE || c.transport == settlementListenerSSE || c.transport == settlementListenerGET
}

func (c settlementCell) exclusion() string {
	switch {
	case c.deferred && c.transport != settlementStdio && c.transport != settlementBridgeJSON && c.transport != settlementBridgeSSE:
		return "deferred release is implemented by the subprocess and HTTP bridge"
	case c.transport == settlementListenerGET && c.fault == settlementDuplicate:
		return "GET accepts server requests and notifications, with no pending client request IDs"
	case c.transport == settlementListenerGET && c.fault == settlementOutcomeAppend:
		return "GET has no paired tool-call outcome"
	case c.transport == settlementListenerGET && c.fault == settlementIntentAppend && !c.required:
		return "GET has no admission receipt in best-effort mode"
	case c.sse() && c.fault == settlementReadPartial:
		return "SSE has an event reader instead of a JSON body reader"
	case !c.sse() && c.fault == settlementReadSSE:
		return "transport does not read SSE events"
	case !c.listener() && c.fault == settlementRequestCancel:
		return "stdio input has one session context, with no independently cancellable request"
	case c.bridge() && c.fault == settlementClientCancel:
		return "stdio EOF cannot interrupt the bridge's synchronous POST; session cancellation is covered by shutdown"
	case c.bridge() && c.fault == settlementDuplicate:
		return "the bridge serializes ordinary and released POSTs on its upstream lock"
	default:
		return ""
	}
}

func TestMCPOutcomeFaultMatrix(t *testing.T) {
	for transportID, transportName := range settlementTransports {
		if transportName == "" {
			t.Fatalf("transport %d has no matrix entry", transportID)
		}
		for faultID, faultName := range settlementFaults {
			if faultName == "" {
				t.Fatalf("fault %d has no matrix entry", faultID)
			}
			for _, required := range []bool{false, true} {
				for _, deferred := range []bool{false, true} {
					cell := settlementCell{settlementTransport(transportID), settlementFault(faultID), required, deferred}
					mode, path := "best_effort", "tool_call"
					if required {
						mode = "required"
					}
					if deferred {
						path = "deferred_release"
					}
					t.Run(strings.Join([]string{transportName, path, mode, faultName}, "/"), func(t *testing.T) {
						if reason := cell.exclusion(); reason != "" {
							t.Skip(reason)
						}
						runSettlementCell(t, cell)
					})
				}
			}
		}
	}
}

var errSettlementFault = errors.New("injected I/O failure")

const (
	settlementTool         = "send_tool"
	settlementOtherTool    = "send_other"
	settlementReply        = `{"jsonrpc":"2.0","id":1,"result":{}}`
	settlementNotify       = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"ready"}}`
	settlementBound        = 15 * time.Second
	settlementReady        = "ready"
	settlementStop         = "stop"
	settlementFaultMarker  = "fault-injected"
	settlementObservations = "observations"
	settlementResponses    = "responses"
)

type settlementProbe struct {
	dir   string
	cell  settlementCell
	fault atomic.Int32

	send      chan struct{}
	both      chan struct{}
	release   chan struct{}
	upgraded  chan struct{}
	dialed    chan net.Conn
	allowSend sync.Once
}

func newSettlementProbe(dir string, cell settlementCell) *settlementProbe {
	return &settlementProbe{
		dir: dir, cell: cell, send: make(chan struct{}, 2), both: make(chan struct{}),
		release: make(chan struct{}), upgraded: make(chan struct{}), dialed: make(chan net.Conn, 1),
	}
}

func (p *settlementProbe) stopWaiting() {
	p.allowSend.Do(func() { close(p.release) })
}

func (p *settlementProbe) holdResponse() bool {
	switch p.cell.fault {
	case settlementTimeout, settlementClientCancel, settlementRequestCancel, settlementShutdown:
		return true
	default:
		return false
	}
}

func appendSettlementObservation(dir, name, tool string) error {
	f, err := os.OpenFile(filepath.Clean(filepath.Join(dir, name)), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	_, err = fmt.Fprintln(f, tool)
	return err
}

func settlementObserved(dir, name string) ([]string, error) {
	data, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- test-owned evidence directory.
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return strings.Fields(string(data)), err
}

func settlementToolName(raw []byte) string {
	frame := ParseMCPFrame(raw)
	return frame.RoutingName
}

func recordSettlementSend(dir, tool string) error {
	if _, err := os.Stat(filepath.Join(dir, "synced-"+tool)); err == nil {
		tool += ":synced"
	}
	return appendSettlementObservation(dir, settlementObservations, tool)
}

func (p *settlementProbe) observeSend(t *testing.T, tool string) {
	t.Helper()
	if err := recordSettlementSend(p.dir, tool); err != nil {
		t.Error(err)
	}
	p.send <- struct{}{}
}

func (p *settlementProbe) observeResponse(t *testing.T, tool string) {
	t.Helper()
	if err := appendSettlementObservation(p.dir, settlementResponses, tool); err != nil {
		t.Error(err)
	}
}

type settlementConn struct {
	net.Conn
	fail func() bool
}

func (c settlementConn) Write(b []byte) (int, error) {
	if c.fail() {
		_ = c.Close()
		return 0, errSettlementFault
	}
	return c.Conn.Write(b)
}

type settlementOutput struct {
	p       *settlementProbe
	written chan struct{}
}

func (o settlementOutput) Write(b []byte) (int, error) {
	select {
	case o.written <- struct{}{}:
	default:
	}
	if o.p.cell.fault == settlementWriteClient {
		o.p.fault.Add(1)
		return 0, errSettlementFault
	}
	return len(b), nil
}

func (p *settlementProbe) dial(ctx context.Context, network, address string) (net.Conn, error) {
	if p.cell.fault == settlementDial {
		p.fault.Add(1)
		return nil, errSettlementFault
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	if p.cell.fault == settlementTimeout && (p.cell.transport == settlementWebSocket || p.cell.listener()) {
		p.dialed <- conn
	}
	if p.cell.fault != settlementWriteUpstream {
		return conn, nil
	}
	return settlementConn{Conn: conn, fail: func() bool {
		if p.cell.transport == settlementWebSocket {
			select {
			case <-p.upgraded:
			default:
				return false
			}
		}
		p.fault.Add(1)
		return true
	}}, nil
}

func (p *settlementProbe) httpUpstream(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tool := http.MethodGet
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			tool = settlementToolName(body)
		} else if p.cell.transport != settlementListenerGET || r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p.cell.fault == settlementDuplicate && tool == settlementOtherTool {
			close(p.both)
		}
		p.observeSend(t, tool)
		if p.cell.fault == settlementDuplicate && tool == settlementTool {
			select {
			case <-p.both:
			case <-r.Context().Done():
				return
			}
		}
		controller := http.NewResponseController(w)
		w.Header().Set("Content-Type", "application/json")
		if p.cell.sse() {
			w.Header().Set("Content-Type", "text/event-stream")
		}
		if p.cell.fault == settlementReadEmpty {
			w.Header().Set("Content-Length", "20")
			w.WriteHeader(http.StatusOK)
			p.fault.Add(1)
			return
		}
		if p.cell.fault == settlementReadPartial || p.cell.fault == settlementReadSSE {
			w.Header().Set("Content-Length", "2048")
			fragment := "{\"jsonrpc\""
			if p.cell.sse() {
				fragment = "data: " + fragment
			}
			_, _ = io.WriteString(w, fragment)
			p.fault.Add(1)
			return
		}
		if p.holdResponse() || p.cell.fault == settlementDuplicate && tool == settlementOtherTool {
			w.WriteHeader(http.StatusOK)
			_ = controller.Flush()
			select {
			case <-p.release:
			case <-r.Context().Done():
			}
			return
		}

		body := settlementReply
		if r.Method == http.MethodGet {
			body = settlementNotify
		}
		if p.cell.fault == settlementScanError {
			body = malformedSettlementReply(body)
			p.fault.Add(1)
		} else {
			p.observeResponse(t, tool)
		}
		if p.cell.sse() {
			body = "data: " + body + "\n\n"
		}
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)
	t.Cleanup(p.stopWaiting)
	return server.URL
}

func (p *settlementProbe) wsUpstream(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		close(p.upgraded)
		raw, _, err := wsio.ReadClientData(conn)
		if err != nil {
			if p.cell.fault != settlementWriteUpstream && p.cell.fault != settlementIntentAppend {
				t.Error(err)
			}
			return
		}
		tool := settlementToolName(raw)
		p.observeSend(t, tool)
		switch p.cell.fault {
		case settlementReadEmpty:
			p.fault.Add(1)
			return
		case settlementReadPartial:
			_ = ws.WriteHeader(conn, ws.Header{Fin: true, OpCode: ws.OpText, Length: 40})
			_, _ = io.WriteString(conn, "{")
			p.fault.Add(1)
			return
		case settlementDuplicate:
			second, _, readErr := wsio.ReadClientData(conn)
			if readErr != nil {
				return
			}
			p.observeSend(t, settlementToolName(second))
		}
		if p.holdResponse() {
			_ = conn.SetReadDeadline(time.Now().Add(settlementBound))
			_, _, _ = wsio.ReadClientData(conn)
			return
		}
		body := settlementReply
		if p.cell.fault == settlementScanError {
			body = malformedSettlementReply(body)
			p.fault.Add(1)
		} else {
			p.observeResponse(t, tool)
		}
		_ = wsio.WriteServerMessage(conn, ws.OpText, []byte(body))
	}))
	t.Cleanup(server.Close)
	return wsURL(server)
}

func (p *settlementProbe) markDurable(f *os.File) error {
	if err := f.Sync(); err != nil {
		return err
	}
	entries, err := recorder.ReadEntries(f.Name())
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type != actionReceiptEntryType {
			continue
		}
		r, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			return err
		}
		a := r.ActionRecord
		if a.DecisionPhase == receipt.DecisionPhaseIntent ||
			a.Layer == "mcp_transport_admission" {
			tool := strings.TrimPrefix(a.Target, "tool:")
			if a.Method == http.MethodGet {
				tool = http.MethodGet
			}
			if tool == settlementTool || tool == settlementOtherTool || tool == http.MethodGet {
				if err := os.WriteFile(filepath.Join(p.dir, "synced-"+tool), nil, 0o600); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (p *settlementProbe) appendGuard(e recorder.Entry) error {
	if e.Type != actionReceiptEntryType {
		return nil
	}
	raw, ok := e.Detail.(json.RawMessage)
	if !ok {
		return nil
	}
	r, err := receipt.Unmarshal(raw)
	if err != nil {
		return err
	}
	a := r.ActionRecord
	switch p.cell.fault {
	case settlementIntentAppend:
		intent := a.DecisionPhase == receipt.DecisionPhaseIntent ||
			p.cell.transport == settlementListenerGET && a.Layer == "mcp_transport_admission"
		if intent && p.fault.CompareAndSwap(0, 1) {
			return errSettlementFault
		}
	case settlementOutcomeAppend:
		if a.DecisionPhase == receipt.DecisionPhaseOutcome && p.fault.CompareAndSwap(0, 1) {
			return errSettlementFault
		}
	}
	return nil
}

func runSettlementCell(t *testing.T, cell settlementCell) {
	t.Helper()
	opts, rec, dir, _ := newMCPTransportReceiptGroup(t)
	open, _ := opts.ReceiptGroup.Shards.Opening()
	probe := newSettlementProbe(dir, cell)
	opts.Scanner = testInputScanner(t)
	opts.RequireReceipts = cell.required
	opts.Transport = ""
	if cell.transport == settlementStdio {
		opts.Transport = deferred.SurfaceMCPStdio
	}
	opts.DialContext = probe.dial
	if cell.fault == settlementTimeout {
		opts.InputCfg = &InputScanConfig{ResponseTimeoutSeconds: 1}
	}
	rec.SetSyncForTest(probe.markDurable)
	rec.SetReceiptAppendGuardForTest(probe.appendGuard)

	if cell.deferred {
		opts.DeferManager = newDeferKillManager(t)
		opts.PolicyCfg = deferApprovalPolicy(config.DeferResolverProfile{})
		opts.PolicyCfg.Rules[0].ResolutionPolicy.ResolverProfile = ""
	}

	ctx, cancel := context.WithTimeout(t.Context(), settlementBound)
	defer cancel()
	switch cell.transport {
	case settlementStdio, settlementBridgeJSON, settlementBridgeSSE, settlementWebSocket:
		probe.runStdio(t, ctx, cancel, opts)
	case settlementListenerJSON, settlementListenerSSE, settlementListenerGET:
		probe.runListener(t, ctx, cancel, opts)
	default:
		t.Fatal("transport has no matrix driver")
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}
	probe.assertReceipts(t, open.SignerKey)
}

func (p *settlementProbe) assertReceipts(t *testing.T, signer string) {
	t.Helper()
	sends, err := settlementObserved(p.dir, settlementObservations)
	if err != nil {
		t.Fatal(err)
	}
	replies, err := settlementObserved(p.dir, settlementResponses)
	if err != nil {
		t.Fatal(err)
	}
	seenSends, seenReplies := make(map[string]int), make(map[string]int)
	for _, send := range sends {
		tool, durable := strings.CutSuffix(send, ":synced")
		seenSends[tool]++
		if p.cell.required && !durable {
			t.Errorf("P3: upstream received %s without durable admission", tool)
		}
	}
	for _, tool := range replies {
		seenReplies[tool]++
	}

	wantSends := 1
	switch p.cell.fault {
	case settlementDial, settlementWriteUpstream:
		wantSends = 0
	case settlementIntentAppend:
		if p.cell.required || p.cell.deferred {
			wantSends = 0
		}
	case settlementDuplicate:
		wantSends = 2
	}
	if len(sends) != wantSends {
		t.Errorf("upstream sends = %v, want %d", sends, wantSends)
	}
	if p.cell.fault != settlementSuccess && p.fault.Load() == 0 {
		if _, err := os.Stat(filepath.Join(p.dir, settlementFaultMarker)); err != nil {
			t.Error("injection point was not reached")
		}
	}

	p.assertSettlePairs(t, signer, seenSends, seenReplies)
}

func (p *settlementProbe) assertSettlePairs(t *testing.T, signer string, sends, replies map[string]int) {
	t.Helper()
	type located struct {
		action receipt.ActionRecord
		shard  string
	}
	intents := make(map[string]located)
	terminals := make(map[string][]located)
	approvals := make(map[string]located)
	corrections := make(map[string][]located)
	var getAdmissions int
	paths, err := filepath.Glob(filepath.Join(p.dir, "evidence-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		entries, err := recorder.ReadEntries(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Type != actionReceiptEntryType {
				continue
			}
			r, err := receipt.Unmarshal(entry.RawDetail)
			if err != nil {
				t.Fatal(err)
			}
			if err := receipt.VerifyWithKey(r, signer); err != nil {
				t.Fatal(err)
			}
			a := r.ActionRecord
			loc := located{action: a, shard: entry.SessionID}
			if a.Layer == "mcp_transport_admission" && a.Method == http.MethodGet {
				getAdmissions++
			}
			switch a.DecisionPhase {
			case receipt.DecisionPhaseIntent:
				intents[a.ActionID] = loc
			case receipt.DecisionPhaseOutcome:
				terminals[a.ActionID] = append(terminals[a.ActionID], loc)
			case receipt.DecisionPhaseResolution:
				switch a.Verdict {
				case config.ActionAllow:
					approvals[a.ParentActionID] = loc
				case config.ActionBlock:
					corrections[a.ParentActionID] = append(corrections[a.ParentActionID], loc)
				}
			}
		}
	}
	for id, intent := range intents {
		if parent := intent.action.ParentActionID; p.cell.deferred && parent != "" {
			approval, ok := approvals[parent]
			if !ok || approval.shard != intent.shard || approval.action.Target != intent.action.Target {
				t.Errorf("P1/P4: release intent for %s did not use the approval's identity and shard", intent.action.Target)
			}
			delete(approvals, parent)
		}
		terminal := terminals[id]
		if len(terminal) != 1 {
			t.Errorf("P1: %s %s has %d terminal settlements", intent.action.Target, intent.action.DecisionPhase, len(terminal))
		}
		for _, got := range terminal {
			if got.shard != intent.shard || got.action.Target != intent.action.Target {
				t.Errorf("P4: %s on shard %s settled %s on shard %s", got.action.Target, got.shard, intent.action.Target, intent.shard)
			}
			tool := strings.TrimPrefix(intent.action.Target, "tool:")
			status, _, _ := strings.Cut(got.action.Pattern, " ")
			if p.cell.fault == settlementSuccess && status != "status=result" {
				t.Errorf("successful call did not record its response: %s", got.action.Pattern)
			}
			switch status {
			case "status=forwarded":
				if sends[tool] == 0 {
					t.Errorf("P2: receipt claimed send for %s without an observed send", tool)
				}
				sends[tool]--
			case "status=result", "status=completed":
				if sends[tool] == 0 || replies[tool] == 0 {
					t.Errorf("P2/P4: receipt claimed completion for %s without its upstream response", tool)
				}
				sends[tool]--
				replies[tool]--
				if p.cell.fault == settlementWriteClient {
					t.Errorf("response was recorded as delivered after a failed downstream write: %s", got.action.Pattern)
				}
			}
		}
		delete(terminals, id)
	}
	for _, unmatched := range terminals {
		for _, got := range unmatched {
			t.Errorf("P4: %s %s has no owning admission", got.action.Target, got.action.Pattern)
		}
	}
	if p.cell.deferred {
		for id, approval := range approvals {
			corrected := corrections[id]
			if p.cell.fault != settlementIntentAppend || len(corrected) != 1 || corrected[0].shard != approval.shard {
				t.Errorf("P1: approval for %s has no release intent or same-shard correction", approval.action.Target)
			}
		}
	}
	if p.cell.transport == settlementListenerGET {
		wantAdmissions := 0
		if p.cell.required && p.cell.fault != settlementIntentAppend {
			wantAdmissions = 1
		}
		if getAdmissions != wantAdmissions {
			t.Errorf("GET admissions = %d, want %d", getAdmissions, wantAdmissions)
		}
	}
	if len(intents) == 0 && p.cell.transport != settlementListenerGET && p.cell.fault != settlementIntentAppend &&
		!p.cell.subprocessStartFailure() {
		t.Error("test did not produce an admission receipt")
	}
}
