// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
)

// sseMessageWriter writes each scanned JSON-RPC message as one SSE event.
// It is used by the HTTP listener when the upstream POST response is
// text/event-stream so clean messages reach the downstream client as soon as
// ForwardScanned accepts them, instead of buffering the whole stream to EOF.
type sseMessageWriter struct {
	mu             sync.Mutex
	w              io.Writer
	responseWriter http.ResponseWriter
	writeTimeout   time.Duration
	flusher        http.Flusher
	wrote          bool
}

var _ transport.MessageWriter = (*sseMessageWriter)(nil)

// requestDoneReader runs release before reading past the request's own
// response. ForwardScanned reads the next message only after it has finished
// the previous one (scan, delivery or denial, and inventory commit), so a
// stream the upstream keeps open for later events cannot extend a hold that
// belongs to the request, whether its response was delivered, empty or denied.
type requestDoneReader struct {
	transport.MessageReader
	tracker *RequestTracker
	release func()
}

func (r *requestDoneReader) ReadMessage() ([]byte, error) {
	if !r.tracker.HasPending() {
		r.release()
	}
	return r.MessageReader.ReadMessage()
}

type listenerStateMessageWriter struct {
	opts   MCPProxyOpts
	denied bool
	state  *mcpListenerClientState
	writer transport.MessageWriter
}

func (w *listenerStateMessageWriter) WriteMessage(msg []byte) error {
	var writeErr error
	if !w.state.commitIfActive(func() {
		writeErr = w.writer.WriteMessage(msg)
	}) {
		w.denied = true
		dropMCPDenial(w.opts, mcpListenerAdmissionDenialAudit(), "response")
		return context.Canceled
	}
	return writeErr
}

func (sw *sseMessageWriter) WriteMessage(msg []byte) error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if sw.responseWriter != nil && sw.writeTimeout > 0 {
		controller := http.NewResponseController(sw.responseWriter)
		if err := controller.SetWriteDeadline(time.Now().Add(sw.writeTimeout)); err == nil {
			defer func() { _ = controller.SetWriteDeadline(time.Time{}) }()
		}
	}
	if len(msg) > transport.MaxLineSize {
		return fmt.Errorf("message too large: %d bytes", len(msg))
	}
	// The first write may commit headers even when it fails part way. Wrote
	// must reflect that attempt so the handler aborts instead of appending a
	// synthetic 502 response to a partially written event.
	sw.wrote = true
	if listener, ok := sw.w.(*mcpListenerDenialWriter); ok && listener.pendingAdaptiveRefusal() {
		// Before the first event, the listener can still send its fixed HTTP
		// refusal. Give it the whole message so it retains the JSON-RPC ID;
		// parsing an SSE prefix would lose it. Started streams keep SSE framing.
		if _, err := (httpstream.Writer{Writer: sw.w}).Write(msg); err != nil {
			return fmt.Errorf("writing adaptive refusal: %w", err)
		}
	} else {
		lines := bytes.Split(msg, []byte("\n"))
		for _, line := range lines {
			if _, err := (httpstream.Writer{Writer: sw.w}).Write([]byte("data: ")); err != nil {
				return fmt.Errorf("writing sse data prefix: %w", err)
			}
			if _, err := (httpstream.Writer{Writer: sw.w}).Write(line); err != nil {
				return fmt.Errorf("writing sse data: %w", err)
			}
			if _, err := (httpstream.Writer{Writer: sw.w}).Write([]byte("\n")); err != nil {
				return fmt.Errorf("writing sse line terminator: %w", err)
			}
		}
		if _, err := (httpstream.Writer{Writer: sw.w}).Write([]byte("\n")); err != nil {
			return fmt.Errorf("writing sse event terminator: %w", err)
		}
	}
	if sw.flusher != nil {
		if sw.responseWriter != nil {
			if err := http.NewResponseController(sw.responseWriter).Flush(); err != nil {
				return fmt.Errorf("flushing sse event: %w", err)
			}
		} else {
			sw.flusher.Flush()
		}
	}
	return nil
}

func (sw *sseMessageWriter) Wrote() bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return sw.wrote
}

// startGETStream maintains a background GET SSE connection for server-initiated
// messages. Called after the initialize handshake establishes a session ID.
// Reconnects with exponential backoff (1s base, 30s cap) on stream end or
// transient errors. Exits permanently only on transport.ErrStreamNotSupported (HTTP 405)
// or context cancellation.
// opts carries Scanner, Approver, ToolCfg, KillSwitch, Rec, AdaptiveCfg, and
// Metrics through to ForwardScanned for adaptive enforcement.
func startGETStream(
	ctx context.Context,
	httpClient *transport.HTTPClient,
	safeClientOut *syncWriter,
	safeLogW *syncWriter,
	opts MCPProxyOpts,
	tracker *RequestTracker,
	wg *sync.WaitGroup,
) {
	wg.Add(1)
	go func() {
		defer wg.Done()

		backoff := time.Second
		const maxBackoff = 30 * time.Second

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Kill switch: pause reconnecting while active. Without this,
			// the retry loop keeps establishing outbound connections even
			// though ForwardScanned blocks every message. Wait here instead
			// of returning so the goroutine resumes when the switch clears.
			if opts.KillSwitch != nil && opts.KillSwitch.IsActive() {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream paused: kill switch active\n")
				for opts.KillSwitch.IsActive() {
					select {
					case <-ctx.Done():
						return
					case <-time.After(time.Second):
					}
				}
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream resuming: kill switch cleared\n")
			}

			scanErr, err := scanGETStream(ctx, httpClient, safeClientOut, safeLogW, opts, tracker)
			if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(err, ael.ErrCapacity) {
				return
			}
			if err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream: %v\n", err)
				// Permanent error - server does not support GET streams.
				if errors.Is(err, transport.ErrStreamNotSupported) {
					return
				}
				// Transient error - backoff and retry.
				select {
				case <-ctx.Done():
					return
				case <-time.After(backoff):
				}
				backoff *= 2
				if backoff > maxBackoff {
					backoff = maxBackoff
				}
				continue
			}

			// Reset backoff on successful connection.
			backoff = time.Second

			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: GET stream scan error: %v\n", scanErr)
				logMCPIncompleteResponse(safeLogW, opts, http.MethodGet, scanErr)
			}

			// Stream ended - reconnect with backoff unless cancelled.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
		}
	}()
}

func (w *listenerStateMessageWriter) writeDeniedMessage(msg []byte) error {
	w.denied = true
	var err error
	if !w.state.commitIfActive(func() { err = deliverMCPDeniedMessage(w.writer, msg) }) {
		return context.Canceled
	}
	return err
}

// scanGETStream returns stream and setup errors separately so reconnect keeps
// its existing backoff and terminal-error handling.
func scanGETStream(ctx context.Context, client *transport.HTTPClient, writer transport.MessageWriter, logW io.Writer, opts MCPProxyOpts, tracker *RequestTracker) (scanErr, setupErr error) {
	admission, err := opts.admitNativeRequest()
	if err != nil {
		return nil, err
	}
	defer admission.ReleaseNativeAdmission()
	streamCtx, stop := httpstream.WithCapacityGrace(ctx, nil, admission.NativeLease, opts.shutdownGrace())
	defer stop()
	opts.nativeAdmission = admission
	transportReceiptOpts := opts.snapshotScanPolicy().pinReceiptWriters()
	transportAdmission, err := admitDurableTransport(transportReceiptOpts, http.MethodGet, opts.AuthorityDestination)
	if err != nil {
		logReceiptEmitFailure(logW, err, true, config.ActionForward)
		return nil, err
	}
	effect := mcpV3NetworkExchange{ctx: streamCtx, opts: transportReceiptOpts, log: logW}
	if err := effect.admit(MCPFrame{Method: http.MethodGet}, transportAdmission.ActionID); err != nil {
		return nil, err
	}
	defer effect.finish()
	if effect.send != nil && streamCtx.Err() != nil {
		return nil, streamCtx.Err()
	}
	effect.sent = true
	reader, err := client.OpenObservedGETStream(streamCtx, effect.observe)
	if err != nil {
		switch {
		case errors.Is(context.Cause(streamCtx), ael.ErrCapacity):
			warnTransportAdmission(logW, transportReceiptOpts, transportAdmission, nativeCapacityReason)
			err = ael.ErrCapacity
		case httpstream.Reason(streamCtx, err) == httpstream.Cancelled:
			recordTransportAdmissionResult(logW, transportReceiptOpts, transportAdmission, "cancelled", httpstream.Cancelled)
		default:
			warnTransportAdmission(logW, transportReceiptOpts, transportAdmission, "upstream_error")
		}
		return nil, err
	}
	warnContext, stopWarnings := opts.nativeWarningContext(streamCtx, admission)
	opts.WarnContext = warnContext
	// Subscription events are independent of pending POST replies.
	opts.v3Session = nil
	defer stopWarnings()

	_, scanErr = scanMCPHTTPResponse(streamCtx, reader, effect.streamWriter(writer), logW, tracker, opts)
	if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(context.Cause(streamCtx), ael.ErrCapacity) {
		if transportAdmission.ActionID != "" {
			recordTransportAdmissionResult(logW, transportReceiptOpts, transportAdmission, "cancelled", nativeCapacityReason)
		} else {
			recordListenerStreamError(ctx, logW, opts, TrackedRequestOutcome{Receipt: mcpStreamReceipt(opts, http.MethodGet)}, true, ael.ErrCapacity)
		}
		return ael.ErrCapacity, nil
	}

	if transportAdmission.ActionID != "" {
		switch {
		case scanErr == nil && streamCtx.Err() == nil:
			recordTransportAdmissionResult(logW, transportReceiptOpts, transportAdmission, "completed", "stream_completed")
		case httpstream.Reason(streamCtx, scanErr) == httpstream.Cancelled:
			recordTransportAdmissionResult(logW, transportReceiptOpts, transportAdmission, "cancelled", httpstream.Cancelled)
		default:
			warnTransportAdmission(logW, transportReceiptOpts, transportAdmission, httpstream.Incomplete)
		}
	} else if errors.Is(scanErr, transport.ErrIncompleteResponse) && ctx.Err() == nil {
		// A subscription has no pending request identity. Sign its own
		// terminal diagnostic while its stream reservation is active.
		emitMCPStandaloneStreamReceipt(opts, logW, mcpStreamReceipt(opts, http.MethodGet), "200", httpstream.Incomplete)
	}
	return scanErr, nil
}
