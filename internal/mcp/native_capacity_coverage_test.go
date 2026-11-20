// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestHTTPListenerCapacitySettlesAlreadyOpenSSE(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sendResult bool
	}{{"before first event", false}, {"after admitted result", true}} {
		t.Run(tc.name, func(t *testing.T) {
			e, dir := newNativeMCPEmitter(t, nativeMCPRequestRecords+nativeMCPEventRecords+4)
			ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(4*time.Second))
			defer cancel()
			entered, stop := make(chan struct{}), make(chan struct{})
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if _, err := io.Copy(io.Discard, r.Body); err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				if tc.sendResult {
					if _, err := fmt.Fprintf(w, "data: %s\n\n", cleanToolsCallResponse); err != nil {
						t.Error(err)
						return
					}
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				close(entered)
				select {
				case <-stop:
				case <-r.Context().Done():
					return
				case <-ctx.Done():
					return
				}
				const late = `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"late fixture"}}`
				if _, err := fmt.Fprintf(w, "data: %s\n\n", late); err != nil {
					t.Error(err)
					return
				}
				if err := http.NewResponseController(w).Flush(); err != nil {
					t.Error(err)
					return
				}
				<-r.Context().Done()
			}))
			defer upstream.Close()

			opts := MCPProxyOpts{Scanner: testScannerForHTTP(t), ReceiptEmitter: e, RequireReceipts: true, ListenerShutdownTimeout: 2 * time.Second}
			baseURL, _ := startListenerProxyWithOpts(t, upstream.URL, opts)
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/", strings.NewReader(cleanToolsCallRequest))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			type result struct {
				status            int
				body              string
				readErr, closeErr error
			}
			firstEvent, clientResult := make(chan result, 1), make(chan result, 1)
			go func() {
				resp, err := upstream.Client().Do(req)
				if err != nil {
					clientResult <- result{readErr: err}
					return
				}
				reader := bufio.NewReader(resp.Body)
				if tc.sendResult {
					line, err := reader.ReadString('\n')
					firstEvent <- result{status: resp.StatusCode, body: line, readErr: err}
				}
				body, err := io.ReadAll(reader)
				closeErr := resp.Body.Close()
				clientResult <- result{status: resp.StatusCode, body: string(body), readErr: err, closeErr: closeErr}
			}()
			select {
			case <-entered:
			case <-ctx.Done():
				t.Fatal("tool request did not reach the SSE endpoint")
			}
			if tc.sendResult {
				select {
				case first := <-firstEvent:
					if first.status != http.StatusOK || first.readErr != nil || !strings.Contains(first.body, `"result"`) {
						t.Fatalf("admitted SSE result = %d %q, %v", first.status, first.body, first.readErr)
					}
				case <-ctx.Done():
					t.Fatal("client did not receive the admitted SSE result")
				}
			}
			if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
				t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
			}
			late, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/", strings.NewReader(cleanToolsCallRequest))
			if err != nil {
				t.Fatal(err)
			}
			late.Header.Set("Content-Type", "application/json")
			late.Header.Set("Accept", "application/json, text/event-stream")
			refused, err := upstream.Client().Do(late)
			if err != nil {
				t.Fatal(err)
			}
			refusalBody, readErr := io.ReadAll(refused.Body)
			closeErr := refused.Body.Close()
			if readErr != nil || closeErr != nil || refused.StatusCode != http.StatusServiceUnavailable ||
				string(refusalBody) != ael.ErrCapacity.Error()+"\n" {
				t.Fatalf("new MCP admission at capacity = %d %q, read=%v close=%v", refused.StatusCode, refusalBody, readErr, closeErr)
			}
			close(stop)
			select {
			case got := <-clientResult:
				if got.closeErr != nil {
					t.Fatal(got.closeErr)
				}
				if !tc.sendResult {
					if got.readErr != nil || got.status != http.StatusServiceUnavailable || got.body != ael.ErrCapacity.Error()+"\n" {
						t.Fatalf("pre-SSE refusal = %d %q, %v", got.status, got.body, got.readErr)
					}
				} else if !errors.Is(got.readErr, io.ErrUnexpectedEOF) || strings.Contains(got.body, "late fixture") {
					t.Fatalf("post-result cutoff = %q, %v", got.body, got.readErr)
				}
			case <-ctx.Done():
				t.Fatal("client did not receive the SSE terminal result")
			}
			select {
			case <-e.NativeCapacity().Drained():
			case <-ctx.Done():
				t.Fatal("SSE admission did not drain")
			}
			verifyMCPNativeClose(t, e, dir)
			entries, err := recorder.QuerySession(dir, e.Session(), &recorder.QueryFilter{Type: "action_receipt"})
			if err != nil {
				t.Fatal(err)
			}
			var intentID string
			var terminal receipt.ActionRecord
			var count int
			for _, entry := range entries.Entries {
				signed, err := receipt.Unmarshal(entry.RawDetail)
				if err != nil {
					t.Fatal(err)
				}
				if signed.ActionRecord.DecisionPhase == receipt.DecisionPhaseIntent {
					intentID = signed.ActionRecord.ActionID
				}
				if signed.ActionRecord.Pattern != "status=200 bytes=unknown reason="+nativeCapacityReason {
					continue
				}
				if err := receipt.VerifyWithKey(signed, e.SignerKeyHex()); err != nil {
					t.Fatal(err)
				}
				terminal = signed.ActionRecord
				count++
			}
			if count != 1 {
				t.Fatalf("capacity receipts = %d, want one", count)
			}
			if terminal.DecisionPhase != receipt.DecisionPhaseOutcome || intentID == "" {
				t.Fatalf("intent = %q, terminal phase = %q", intentID, terminal.DecisionPhase)
			}
			if (terminal.ActionID == intentID) == tc.sendResult {
				t.Fatalf("unexpected capacity outcome correlation: intent=%q terminal=%q", intentID, terminal.ActionID)
			}
		})
	}
}

func TestNativeOutputDeadlineWakesWriter(t *testing.T) {
	writer, reader := net.Pipe()
	t.Cleanup(func() {
		for _, conn := range []net.Conn{writer, reader} {
			if err := conn.Close(); err != nil {
				t.Error(err)
			}
		}
	})
	result := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "fixture")
		result <- err
	}()
	interruptNativeOutput(writer)
	select {
	case err := <-result:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write at cutoff = %v, want %v", err, os.ErrDeadlineExceeded)
		}
	case <-time.After(testwait.Deadline(time.Second)):
		t.Fatal("supported output deadline did not wake the writer")
	}
}

func TestNativeOutcomeRefusesAnInsufficientReservation(t *testing.T) {
	e, _ := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	admission, err := e.AdmitNative(receipt.EmitOpts{}, nativeMCPPendingRecords-1)
	if err != nil {
		t.Fatal(err)
	}
	defer admission.ReleaseNativeAdmission()
	tracker := NewRequestTracker()
	id := json.RawMessage("1")
	if err := trackNativeOutcome(tracker, id, TrackedRequestOutcome{Receipt: admission, Method: methodToolsCall}); !errors.Is(err, ael.ErrInvalidLease) {
		t.Fatalf("tracked outcome refusal = %v, want %v", err, ael.ErrInvalidLease)
	}
	if _, present := tracker.Consume(id); present {
		t.Fatal("refused outcome remained tracked")
	}
}

func TestNativeOutcomeTrackerRefusesBeforeEvictingAnAdmission(t *testing.T) {
	e, _ := newNativeMCPEmitter(t, nativeMCPRequestRecords+4)
	parent, err := e.AdmitNative(receipt.EmitOpts{}, 2*nativeMCPPendingRecords)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.ReleaseNativeAdmission()
	var absent *RequestTracker
	id := json.RawMessage("1")
	if admission := absent.nativeAdmission(id); admission.NativeLease != nil {
		t.Fatal("absent tracker returned a reservation")
	}

	tracker := NewRequestTracker()
	pending := TrackedRequestOutcome{Receipt: parent, Method: methodToolsCall}
	if err := trackNativeOutcome(tracker, id, pending); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { emitPendingIncompleteOutcomes(io.Discard, tracker, MCPProxyOpts{}, "test_complete") })
	for n := 2; n <= maxTrackedRequests; n++ {
		tracker.Track(json.RawMessage(fmt.Sprintf("%d", n)))
	}
	fullID := json.RawMessage(fmt.Sprintf("%d", maxTrackedRequests+1))
	const refusal = "could not reserve a pending receipt outcome for this request ID"
	if err := trackNativeOutcome(tracker, fullID, pending); err == nil || err.Error() != refusal {
		t.Fatalf("full tracker admission = %v, want %q", err, refusal)
	}
	if tracker.nativeAdmission(id).NativeLease == nil || tracker.nativeAdmission(fullID).NativeLease != nil {
		t.Fatal("full tracker replaced the admitted outcome")
	}
	parent.ReleaseNativeAdmission()
	if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
	}
	emitPendingIncompleteOutcomes(io.Discard, tracker, MCPProxyOpts{}, "test_complete")
	select {
	case <-e.NativeCapacity().Drained():
	default:
		t.Fatal("refused tracked outcome held native capacity open")
	}
}

func TestEmitTrackedIncompleteOutcomeReleasesNativeReservation(t *testing.T) {
	e, _ := newNativeMCPEmitter(t, 2*nativeMCPPendingRecords)
	parent, err := e.AdmitNative(receipt.EmitOpts{ActionID: "incomplete-scan"}, nativeMCPPendingRecords+4)
	if err != nil {
		t.Fatal(err)
	}
	parent, err = parent.ReserveNativeTerminal()
	if err != nil {
		t.Fatal(err)
	}
	tracker := NewRequestTracker()
	id := json.RawMessage(`7`)
	if err := trackNativeOutcome(tracker, id, TrackedRequestOutcome{Receipt: parent, Method: methodToolsCall}); err != nil {
		t.Fatal(err)
	}
	emitTrackedIncompleteOutcome(io.Discard, tracker, id, "scan_error", MCPProxyOpts{})
	if _, stillTracked := tracker.Consume(id); stillTracked {
		t.Fatal("incomplete outcome remained tracked")
	}
	parent.ReleaseNativeAdmission()
	if _, err := e.ReserveNativeRecords(2 * nativeMCPRequestRecords); !errors.Is(err, ael.ErrCapacity) {
		t.Fatalf("stop = %v, want %v", err, ael.ErrCapacity)
	}
	select {
	case <-e.NativeCapacity().Drained():
	default:
		t.Fatal("incomplete outcome left the native reservation held")
	}
}
