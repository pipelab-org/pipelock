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
	"slices"
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
	settlementListenerDELETE
	settlementTransportCount
)

var settlementTransports = [settlementTransportCount]string{
	settlementStdio:          "stdio_subprocess",
	settlementBridgeJSON:     "stdio_http",
	settlementBridgeSSE:      "http_bridge_sse",
	settlementWebSocket:      "stdio_websocket",
	settlementListenerJSON:   "http_listener",
	settlementListenerSSE:    "http_listener_sse",
	settlementListenerGET:    "http_listener_get",
	settlementListenerDELETE: "http_listener_delete",
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
	settlementUpgradeAppend
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
	settlementUpgradeAppend: "upgrade_admission_append",
}

type settlementCell struct {
	transport    settlementTransport
	fault        settlementFault
	required     bool
	deferred     bool
	notification bool
}

func (c settlementCell) listener() bool { return c.transport >= settlementListenerJSON }

func (c settlementCell) listenerMethod() string {
	switch c.transport {
	case settlementListenerGET:
		return http.MethodGet
	case settlementListenerDELETE:
		return http.MethodDelete
	default:
		return http.MethodPost
	}
}

func (c settlementCell) bridgeLifecycle() bool {
	return c.bridge() && c.fault == settlementSuccess && !c.deferred && !c.notification
}

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
	case c.fault == settlementUpgradeAppend && (c.transport != settlementWebSocket || !c.required):
		return "only required WebSocket opens have an upgrade admission"
	case c.deferred && c.transport != settlementStdio && c.transport != settlementBridgeJSON && c.transport != settlementBridgeSSE:
		return "deferred release is implemented by the subprocess and HTTP bridge"
	case c.transport == settlementListenerDELETE && c.fault != settlementSuccess &&
		c.fault != settlementDial && c.fault != settlementWriteUpstream &&
		(c.fault != settlementIntentAppend || !c.required):
		return "DELETE has no tool-call ID or response stream to exercise"
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
					cell := settlementCell{
						transport: settlementTransport(transportID), fault: settlementFault(faultID), required: required, deferred: deferred,
					}
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
	t.Run("notification", func(t *testing.T) {
		for transportID := settlementStdio; transportID <= settlementListenerJSON; transportID++ {
			for _, required := range []bool{false, true} {
				for _, fault := range []settlementFault{settlementSuccess, settlementWriteUpstream} {
					cell := settlementCell{transport: transportID, fault: fault, required: required, notification: true}
					mode := "best_effort"
					if required {
						mode = "required"
					}
					t.Run(settlementTransports[transportID]+"/"+mode+"/"+settlementFaults[fault], func(t *testing.T) {
						runSettlementCell(t, cell)
					})
				}
			}
		}
	})
}

var errSettlementFault = errors.New("injected I/O failure")

const (
	settlementTool          = "send_tool"
	settlementOtherTool     = "send_other"
	settlementReply         = `{"jsonrpc":"2.0","id":1,"result":{}}`
	settlementHandshake     = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	settlementNotify        = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"ready"}}`
	settlementBound         = 15 * time.Second
	settlementReady         = "ready"
	settlementStop          = "stop"
	settlementFaultMarker   = "fault-injected"
	settlementObservations  = "observations"
	settlementResponses     = "responses"
	settlementWireLog       = "wire"
	settlementSynced        = "synced-actions"
	settlementUpgrade       = "WS"
	settlementSession       = "test-session"
	settlementSessionHeader = "Mcp-Session-Id"
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

	upstream       string
	finishUpstream func()
	subscriptions  atomic.Int32
	syncMu         sync.Mutex
	synced         []string
	forward        []string
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
	if frame.RoutingName != "" {
		return frame.RoutingName
	}
	return frame.Method
}

func settlementSyncMarker(dir, tool string) string {
	return filepath.Join(dir, "synced-"+strings.ReplaceAll(tool, "/", "-"))
}

func recordSettlementSend(dir, tool string) error {
	if _, err := os.Stat(settlementSyncMarker(dir, tool)); err == nil {
		tool += ":synced"
	}
	return appendSettlementObservation(dir, settlementObservations, tool)
}

func (p *settlementProbe) observeSend(t *testing.T, tool string) {
	t.Helper()
	if err := recordSettlementSend(p.dir, tool); err != nil {
		t.Error(err)
	}
	select {
	case p.send <- struct{}{}:
	default:
	}
}

func (p *settlementProbe) observeResponse(t *testing.T, tool string) {
	t.Helper()
	if err := appendSettlementObservation(p.dir, settlementResponses, tool); err != nil {
		t.Error(err)
	}
}

// settlementWire records inbound traffic even when the fixture cannot serve it.
type settlementWire struct {
	Kind      string
	Method    string
	Target    string
	RequestID string
	Synced    []string
	Forward   []string // Appended single-phase candidates for P6.
	Failed    bool
	Unsent    bool
	Exception string
}

func (op settlementWire) String() string {
	return fmt.Sprintf("%s %s %q id=%q", op.Kind, op.Method, op.Target, op.RequestID)
}

func settlementWireRPC(kind string, raw []byte, synced []string) settlementWire {
	frame := ParseMCPFrame(raw)
	target := frame.Method
	if frame.ToolCallName != "" {
		target = frame.ToolCallName
	} else if frame.RoutingName != "" {
		target = frame.RoutingName
	}
	return settlementWire{Kind: kind, Method: frame.Method, Target: target, RequestID: canonicalID(frame.ID), Synced: synced}
}

func recordSettlementWire(dir string, op settlementWire) error {
	data, err := json.Marshal(op)
	if err != nil {
		return err
	}
	return appendSettlementObservation(dir, settlementWireLog, string(data))
}

func (p *settlementProbe) syncedActions(t *testing.T) []string {
	t.Helper()
	actions, err := settlementObserved(p.dir, settlementSynced)
	if err != nil {
		t.Error(err)
	}
	return actions
}

func (p *settlementProbe) observeWire(t *testing.T, op settlementWire) {
	t.Helper()
	if op.Failed {
		p.syncMu.Lock()
		op.Forward = slices.Clone(p.forward)
		p.syncMu.Unlock()
	}
	if err := recordSettlementWire(p.dir, op); err != nil {
		t.Error(err)
	}
}

func (p *settlementProbe) observeOpenFailure(t *testing.T) {
	t.Helper()
	method := p.cell.listenerMethod()
	if p.cell.transport == settlementWebSocket {
		method = settlementUpgrade
	}
	p.observeWire(t, settlementWire{
		Kind: method, Method: method, Target: p.upstream,
		Synced: p.syncedActions(t), Failed: true, Unsent: true,
	})
}

func (p *settlementProbe) observeSendFailure(t *testing.T, kind string) {
	t.Helper()
	msg := deferKillTestCall
	if p.cell.notification {
		msg = settlementHandshake
	}
	op := settlementWireRPC(kind, []byte(msg), p.syncedActions(t))
	op.Failed, op.Unsent = true, true
	p.observeWire(t, op)
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

func (p *settlementProbe) dial(t *testing.T, ctx context.Context, network, address string) (net.Conn, error) {
	t.Helper()
	if p.cell.fault == settlementDial {
		if p.cell.transport == settlementWebSocket || p.cell.listenerMethod() != http.MethodPost {
			p.observeOpenFailure(t)
		} else {
			p.observeSendFailure(t, http.MethodPost)
		}
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
	var failOnce sync.Once
	return settlementConn{Conn: conn, fail: func() bool {
		if p.cell.transport == settlementWebSocket {
			select {
			case <-p.upgraded:
			default:
				return false
			}
		}
		failOnce.Do(func() {
			if p.cell.listenerMethod() != http.MethodPost {
				p.observeOpenFailure(t)
			} else {
				kind := http.MethodPost
				if p.cell.transport == settlementWebSocket {
					kind = settlementUpgrade
				}
				p.observeSendFailure(t, kind)
			}
			p.fault.Add(1)
		})
		return true
	}}, nil
}

func (p *settlementProbe) httpUpstream(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		synced := p.syncedActions(t)
		target := "http://" + r.Host + r.URL.RequestURI()
		op := settlementWire{Kind: r.Method, Method: r.Method, Target: target, Synced: synced}
		tool := r.Method
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				p.observeWire(t, op)
				t.Error(err)
				return
			}
			op = settlementWireRPC(r.Method, body, synced)
			// Internal paginated tools/list discovery has no client request to admit.
			if op.Method == "tools/list" && op.RequestID == "1" && r.Header.Get(listenerMCPMethod) == "tools/list" {
				frame := ParseMCPFrame(body)
				if frame.ProtocolVersionPresent && frame.ClientCapabilitiesPresent {
					op.Exception = "proxy-owned tools/list discovery"
				}
			}
			tool = settlementToolName(body)
		}
		if p.cell.bridge() && r.Method == http.MethodDelete && r.Header.Get(settlementSessionHeader) == settlementSession {
			// The bridge DELETE is best-effort cleanup even if the receipt writer is broken.
			op.Exception = "bridge session cleanup"
			p.observeWire(t, op)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if p.cell.bridgeLifecycle() && r.Method == http.MethodGet {
			op.Failed = p.subscriptions.Add(1) == 1
			p.observeWire(t, op)
			if op.Failed {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = io.WriteString(w, "data: "+settlementNotify+"\n\n")
			if err := http.NewResponseController(w).Flush(); err != nil {
				t.Error(err)
				return
			}
			select {
			case <-p.release:
			case <-r.Context().Done():
			}
			return
		}
		p.observeWire(t, op)
		if r.Method != http.MethodPost && r.Method != p.cell.listenerMethod() {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p.cell.fault == settlementDuplicate && tool == settlementOtherTool {
			close(p.both)
		}
		p.observeSend(t, tool)
		if p.cell.notification {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if p.cell.bridgeLifecycle() {
			w.Header().Set(settlementSessionHeader, settlementSession)
		}
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
	p.upstream = server.URL
	p.finishUpstream = func() {
		p.stopWaiting()
		server.Close()
	}
	return server.URL
}

func (p *settlementProbe) wsUpstream(t *testing.T) string {
	t.Helper()
	var handlers sync.WaitGroup
	upgraded := sync.OnceFunc(func() { close(p.upgraded) })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlers.Add(1)
		defer handlers.Done()
		p.observeWire(t, settlementWire{
			Kind: settlementUpgrade, Method: settlementUpgrade, Target: "ws://" + r.Host + r.URL.RequestURI(),
			Synced: p.syncedActions(t),
		})
		conn, _, _, err := ws.UpgradeHTTP(r, w)
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = conn.Close() }()
		upgraded()
		raw, _, err := wsio.ReadClientData(conn)
		if err != nil {
			if p.cell.fault != settlementWriteUpstream && p.cell.fault != settlementIntentAppend {
				t.Error(err)
			}
			return
		}
		p.observeWire(t, settlementWireRPC(settlementUpgrade, raw, p.syncedActions(t)))
		tool := settlementToolName(raw)
		p.observeSend(t, tool)
		if p.cell.notification {
			return
		}
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
			p.observeWire(t, settlementWireRPC(settlementUpgrade, second, p.syncedActions(t)))
			p.observeSend(t, settlementToolName(second))
		}
		if p.holdResponse() {
			_ = conn.SetReadDeadline(time.Now().Add(settlementBound))
			if extra, _, err := wsio.ReadClientData(conn); err == nil {
				p.observeWire(t, settlementWireRPC(settlementUpgrade, extra, p.syncedActions(t)))
			}
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
	p.upstream = wsURL(server)
	p.finishUpstream = func() {
		server.Close()
		handlers.Wait()
	}
	return p.upstream
}

func settlementAdmission(a receipt.ActionRecord) bool {
	return a.DecisionPhase == receipt.DecisionPhaseIntent ||
		(a.DecisionPhase == receipt.DecisionPhaseResolution && a.Verdict == config.ActionAllow) ||
		(a.DecisionPhase == "" && a.Verdict == config.ActionForward)
}

func (p *settlementProbe) markDurable(f *os.File) error {
	// Read before syncing so an append concurrent with Sync cannot be
	// mistaken for a record covered by this sync.
	entries, err := recorder.ReadEntries(f.Name())
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	p.syncMu.Lock()
	defer p.syncMu.Unlock()
	for _, entry := range entries {
		if entry.Type != actionReceiptEntryType {
			continue
		}
		r, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			return err
		}
		a := r.ActionRecord
		if settlementAdmission(a) && !slices.Contains(p.synced, a.ActionID) {
			p.synced = append(p.synced, a.ActionID)
		}
		if settlementAdmission(a) {
			tool := strings.TrimPrefix(a.Target, "tool:")
			if a.Method == http.MethodGet || a.Method == http.MethodDelete {
				tool = a.Method
			}
			if tool == settlementTool || tool == settlementOtherTool || tool == http.MethodGet || tool == http.MethodDelete || tool == methodNotificationsInitialized {
				if err := os.WriteFile(settlementSyncMarker(p.dir, tool), nil, 0o600); err != nil {
					return err
				}
			}
		}
	}
	next := filepath.Join(p.dir, settlementSynced+".next")
	if err := os.WriteFile(next, []byte(strings.Join(p.synced, "\n")), 0o600); err != nil {
		return err
	}
	return os.Rename(next, filepath.Join(p.dir, settlementSynced))
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
			p.cell.listenerMethod() != http.MethodPost && a.Layer == "mcp_transport_admission"
		if intent && p.fault.CompareAndSwap(0, 1) {
			return errSettlementFault
		}
	case settlementUpgradeAppend:
		if a.Layer == "mcp_transport_admission" && a.Method == settlementUpgrade && p.fault.CompareAndSwap(0, 1) {
			return errSettlementFault
		}
	case settlementOutcomeAppend:
		if a.DecisionPhase == receipt.DecisionPhaseOutcome && p.fault.CompareAndSwap(0, 1) {
			return errSettlementFault
		}
	}
	if a.DecisionPhase == "" && a.Verdict == config.ActionForward {
		p.syncMu.Lock()
		p.forward = append(p.forward, a.ActionID)
		p.syncMu.Unlock()
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
	opts.AuthorityDestination = ""
	if cell.transport == settlementStdio {
		opts.Transport = deferred.SurfaceMCPStdio
	}
	opts.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return probe.dial(t, ctx, network, address)
	}
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
	case settlementListenerJSON, settlementListenerSSE, settlementListenerGET, settlementListenerDELETE:
		probe.runListener(t, ctx, cancel, opts)
	default:
		t.Fatal("transport has no matrix driver")
	}
	if probe.finishUpstream != nil {
		probe.finishUpstream()
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
	case settlementDial, settlementWriteUpstream, settlementUpgradeAppend:
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

	intents := make(map[string]settlementReceipt)
	terminals := make(map[string][]settlementReceipt)
	approvals := make(map[string]settlementReceipt)
	corrections := make(map[string][]settlementReceipt)
	var legacyAdmissions int
	var records []settlementReceipt
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
			loc := settlementReceipt{action: a, shard: entry.SessionID, sequence: entry.Sequence}
			records = append(records, loc)
			if a.Layer == "mcp_transport_admission" && a.Method == p.cell.listenerMethod() {
				legacyAdmissions++
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
	p.assertWireReceipts(t, records)
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
	if p.cell.listenerMethod() != http.MethodPost {
		wantAdmissions := 0
		if p.cell.required && p.cell.fault != settlementIntentAppend {
			wantAdmissions = 1
		}
		if legacyAdmissions != wantAdmissions {
			t.Errorf("%s admissions = %d, want %d", p.cell.listenerMethod(), legacyAdmissions, wantAdmissions)
		}
	}
	if len(intents) == 0 && !p.cell.notification && p.cell.listenerMethod() == http.MethodPost && p.cell.fault != settlementIntentAppend &&
		!p.cell.subprocessStartFailure() && p.cell.fault != settlementUpgradeAppend {
		t.Error("test did not produce an admission receipt")
	}
}

type settlementReceipt struct {
	action   receipt.ActionRecord
	shard    string
	sequence uint64
}

func (op settlementWire) matches(a receipt.ActionRecord) bool {
	// Legacy JSON-RPC receipts identify the operation by its signed target.
	// Transport admissions also carry the HTTP verb or upgrade method.
	target := a.Target
	if op.Method == methodToolsCall {
		target = strings.TrimPrefix(target, "tool:")
	}
	return a.ActionID != "" &&
		(a.Method == op.Method || (a.Method == "" && op.Kind != op.Method)) &&
		target == receipt.SanitizeSignedTarget(op.Target, nil) &&
		(a.RequestID == "" || a.RequestID == op.RequestID)
}

func (op settlementWire) consumeDurableAdmission(admissions map[string]settlementReceipt, used map[string]bool) bool {
	for _, id := range op.Synced {
		a := admissions[id].action
		if !op.matches(a) {
			continue
		}
		// The allow resolution and release intent authorize the same send.
		key := a.ActionID
		if a.ParentActionID != "" {
			key = a.ParentActionID
		}
		if !used[key] {
			used[key] = true
			return true
		}
	}
	return false
}

func (p *settlementProbe) assertWireReceipts(t *testing.T, records []settlementReceipt) {
	t.Helper()
	file, err := os.Open(filepath.Join(p.dir, settlementWireLog)) // #nosec G304 -- test-owned evidence directory.
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	admissions := make(map[string]settlementReceipt)
	failures := make(map[string][]settlementReceipt)
	for _, record := range records {
		a := record.action
		if settlementAdmission(a) {
			admissions[a.ActionID] = record
		}
		if a.DecisionPhase == "" && a.Layer == mcpOutcomeLayer && a.Verdict == config.ActionWarn &&
			strings.HasPrefix(a.Pattern, "status=error ") {
			failures[a.ActionID] = append(failures[a.ActionID], record)
		}
	}
	used := make(map[string]bool)
	usedForward := make(map[string]bool)
	var bridgeGets, bridgeDeletes int
	decoder := json.NewDecoder(file)
	for {
		var op settlementWire
		if err := decoder.Decode(&op); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if p.cell.bridgeLifecycle() && op.Kind == http.MethodGet {
			bridgeGets++
		}
		switch op.Exception {
		case "bridge session cleanup":
			bridgeDeletes++
			continue
		case "proxy-owned tools/list discovery":
			continue
		}
		if p.cell.required && !op.Unsent && !op.consumeDurableAdmission(admissions, used) {
			t.Errorf("P5: upstream observed %s without a preceding durable record", op)
		}
		// Successful observations also consume any matching admission so a
		// later failed reconnect cannot borrow an earlier action.
		forwardIDs := op.Synced
		if op.Failed {
			forwardIDs = op.Forward
		}
		matchedForward := false
		for _, id := range forwardIDs {
			candidate := admissions[id]
			a := candidate.action
			if a.Verdict != config.ActionForward || usedForward[id] || !op.matches(a) {
				continue
			}
			usedForward[id] = true
			matchedForward = true
			if op.Failed && !slices.ContainsFunc(failures[id], func(failure settlementReceipt) bool {
				return failure.shard == candidate.shard && failure.sequence > candidate.sequence &&
					failure.action.Method == a.Method && failure.action.Target == a.Target
			}) {
				t.Errorf("P6: failed upstream operation %s has no failure record on action %s", op, id)
			}
			break
		}
		if p.cell.required && op.Failed && !matchedForward && (op.Kind == op.Method || p.cell.notification) {
			t.Errorf("expected a single-phase admission for the injected failure of %s", op)
		}
	}
	if p.cell.bridgeLifecycle() && (bridgeGets != 2 || bridgeDeletes != 1) {
		t.Errorf("bridge lifecycle observed GET=%d DELETE=%d, want 2 and 1", bridgeGets, bridgeDeletes)
	}
}
