// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

// RunWSProxy proxies MCP JSON-RPC between stdin/stdout and a WebSocket upstream.
// Messages from stdin are scanned and forwarded as WS text frames to the upstream.
// Messages from the upstream WS connection are scanned and written to stdout.
// Returns when stdin reaches EOF or the upstream connection closes.
// When store is non-nil, a per-invocation session recorder is created and used
// for adaptive enforcement signal recording across both input and response scanning.
func RunWSProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	opts MCPProxyOpts,
) error {
	// Capture before upstream validation and dialing. If the spawning session
	// exits during either step, the watcher must retain the original parent
	// rather than observe PID 1 and become inert.
	startupParentWatch := parentWatchOpts{startPPID: os.Getppid()}
	safeClientOut := newMCPClientWriter(clientOut, opts)
	safeLogW := &syncWriter{w: logW}
	ctx, stopSession, sessionExit := newSessionBoundContext(ctx, startupParentWatch, clientIn, safeLogW, opts.sessionExitForTest)
	defer stopSession()

	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromUpstream(upstreamURL)
	}
	if opts.AuthorityDestination == "" {
		opts.AuthorityDestination = upstreamURL
	}
	if opts.A2ACardURL == "" {
		opts.A2ACardURL = upstreamURL
	}
	opts.A2ACardURL = a2aCardURLForWSUpstream(opts.A2ACardURL)
	startupAuditOpts := opts
	startupAuditOpts.Transport = "mcp_ws"
	if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
		dropMCPDenial(startupAuditOpts, mcpStartupDenialAudit(mcpListenerContractEvalDenialAudit()), "startup")
		return fmt.Errorf("contract upstream evaluation: %w", gateErr)
	} else if gate.Verdict == config.ActionBlock {
		dropMCPDenial(startupAuditOpts, mcpStartupDenialAudit(mcpUpstreamGateDenialAudit(gate)), "startup")
		return fmt.Errorf("contract upstream denied: %s", mcpContractBlockReason(gate))
	}

	// Separate parent and inner context. The parent context comes from
	// signal handling (SIGINT/SIGTERM). The inner context is cancelled
	// when either direction finishes (stdin EOF or upstream close).
	innerCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopInputClose := context.AfterFunc(innerCtx, func() {
		if closer, ok := clientIn.(io.Closer); ok {
			_ = closer.Close()
		}
	})
	defer stopInputClose()
	streamAdmission, err := opts.admitNativeRequest()
	if err != nil {
		return err
	}
	defer streamAdmission.ReleaseNativeAdmission()
	stopCapacityClose := streamAdmission.NativeLease.OnStopAfter(opts.shutdownGrace(), func() {
		cancel()
		interruptNativeOutput(clientOut)
	})
	defer stopCapacityClose()

	// Per-invocation adaptive enforcement recorder.
	var rec session.Recorder
	if opts.Store != nil {
		invocationKey := session.NextInvocationKey("mcp-ws")
		rec = opts.Store.GetOrCreate(invocationKey)
		if rec == nil {
			dropMCPDenial(startupAuditOpts, mcpStartupDenialAudit(mcpListenerCapacityDenialAudit()), "startup")
			return session.ErrCapacity
		}
		defer opts.Store.Delete(invocationKey)
		opts.taskSubject = invocationKey
		session.BindTaskSubject(rec, opts.taskSubject)
	}
	defer recordMCPBaselineSample(opts, rec)

	var wsClient *transport.WSClient

	// Force-close a connection on external cancellation (SIGINT, SIGTERM,
	// parent timeout). Dial eagerly when neither authority verification nor v3
	// receipts gate the upstream connection. Otherwise wait for the first
	// admitted send before opening the connection.
	done := make(chan struct{})
	defer close(done)

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()

	// Tool scanning baseline for this session. ToolCfg from the caller
	// provides the config; each invocation gets its own Baseline so
	// concurrent WS sessions can't contaminate each other's drift state.
	toolCfg := opts.toolCfg()
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  toolCfg.Action,
			DetectDrift:             toolCfg.DetectDrift,
			NewToolAdmission:        toolCfg.NewToolAdmission,
			BindingUnknownAction:    toolCfg.BindingUnknownAction,
			BindingNoBaselineAction: toolCfg.BindingNoBaselineAction,
			ExtraPoison:             toolCfg.ExtraPoison,
			CredentialAcks:          toolCfg.CredentialAcks,
			Now:                     toolCfg.Now,
		}
	}

	const sessionKey = "ws-stdio"

	// Derive the invocation-scoped opts from the caller's shared opts.
	// Override transport-specific fields: the per-invocation recorder,
	// the fwdToolCfg with its private baseline, "mcp_ws" transport, and
	// the always-external-source flag for response-side taint classification.
	wsOpts := opts.withV3Session()
	wsOpts.Rec = rec
	wsOpts.ToolCfg = fwdToolCfg
	wsOpts.ToolCfgFn = nil
	wsOpts.Transport = "mcp_ws"
	wsOpts.TaintExternalSource = true
	replyCtx, stopReply := context.WithCancelCause(innerCtx)
	defer stopReply(nil)
	wsOpts.onLocalV3ReplyFailure = func(err error) {
		stopReply(err)
		cancel()
	}
	wsOpts.WarnContext = innerCtx
	localClientOut := wsOpts.localV3ReplyWriter(safeClientOut, safeLogW, nil)
	wsOpts.sessionExit = sessionExit
	wsOpts.nativeStdio = streamAdmission.NativeLease != nil
	wsOpts.nativeAdmission = streamAdmission

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var lastScanErr error
	var transportAdmission receipt.EmitOpts
	var transportReceiptOpts MCPProxyOpts
	var upstreamEnded bool // read only after the response goroutine is joined
	var upstreamClosedCleanly bool
	var upstreamBlocked bool
	var upstreamWriteFailed bool
	defer func() {
		cancel()
		if wsClient != nil {
			_ = wsClient.Close()
		}
		wg.Wait()
		wsOpts.settleV3Session(innerCtx, safeLogW)
		stopping := streamAdmission.NativeLease.Stopping()
		pendingOutcomes := tracker.DrainPendingOutcomes()
		for _, pending := range pendingOutcomes {
			reason, status := httpstream.Cancelled, "cancelled"
			if upstreamEnded && ctx.Err() == nil {
				reason, status = httpstream.Incomplete, "incomplete"
				if upstreamBlocked && lastScanErr == nil {
					reason, status = "policy_blocked", "blocked"
				}
			}
			if stopping {
				reason, status = nativeCapacityReason, "cancelled"
			}
			pending.Outcome.settle(safeLogW, wsOpts, status, -1, reason)
		}
		if transportAdmission.ActionID != "" && wsClient != nil {
			status, reason := "cancelled", httpstream.Cancelled
			if stopping {
				status, reason = "closed", nativeCapacityReason
			} else if upstreamWriteFailed {
				status, reason = "error", mcpUpstreamWriteFailed
			} else if upstreamEnded && ctx.Err() == nil {
				switch {
				case lastScanErr != nil:
					status, reason = "incomplete", httpstream.Incomplete
				case upstreamBlocked:
					status, reason = "blocked", "policy_blocked"
				case !upstreamClosedCleanly:
					status, reason = "incomplete", httpstream.Incomplete
				default:
					status, reason = "completed", "stream_completed"
				}
			}
			recordTransportAdmissionResult(safeLogW, transportReceiptOpts, transportAdmission, status, reason)
		} else if stopping && wsClient != nil {
			emitMCPStandaloneStreamReceipt(wsOpts, safeLogW, mcpStreamReceipt(wsOpts, "WS"), "closed", nativeCapacityReason)
		} else if len(pendingOutcomes) == 0 && upstreamEnded && ctx.Err() == nil &&
			(errors.Is(lastScanErr, transport.ErrIncompleteResponse) || lastScanErr == nil && !upstreamClosedCleanly && !upstreamBlocked) {
			emitMCPStreamDiagnostic(wsOpts, safeLogW, mcpStreamReceipt(wsOpts, "WS"), "incomplete", httpstream.Incomplete)
		}
	}()

	startUpstream := func() error {
		if wsClient != nil {
			return nil
		}
		var err error
		transportReceiptOpts = wsOpts.snapshotScanPolicy().pinReceiptWriters()
		transportAdmission, err = admitDurableTransport(transportReceiptOpts, "WS", upstreamURL)
		if err != nil {
			logReceiptEmitFailure(safeLogW, err, true, config.ActionForward)
			return fmt.Errorf("recording upstream WebSocket admission: %w", err)
		}
		wsClient, err = transport.NewWSClientWithDialer(innerCtx, upstreamURL, opts.DialContext)
		if err != nil {
			warnTransportAdmission(safeLogW, transportReceiptOpts, transportAdmission, "upstream_handshake_failed")
			return fmt.Errorf("connecting to upstream: %w", err)
		}
		go func(client *transport.WSClient) {
			select {
			case <-innerCtx.Done():
				_ = client.Close()
			case <-done:
			}
		}(wsClient)

		// Upstream -> stdout goroutine: scan responses via ForwardScanned.
		// WSClient implements MessageReader; ForwardScanned loops until EOF.
		wg.Add(1)
		go func(client *transport.WSClient) {
			defer wg.Done()
			defer cancel() // Signal main goroutine if upstream closes first.
			responseOpts := wsOpts
			responseOpts.responseDenial = func(denial *mcpTerminalDecision) {
				upstreamBlocked = true
				if wsOpts.responseDenial != nil {
					wsOpts.responseDenial(denial)
				}
			}
			_, scanErr := ForwardScanned(client, safeClientOut, safeLogW, tracker, responseOpts)
			upstreamEnded = innerCtx.Err() == nil
			upstreamClosedCleanly = client.PeerClosedCleanly()
			if scanErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream scan error: %v\n", scanErr)
				logMCPIncompleteResponse(safeLogW, wsOpts, "WS", scanErr)
				lastScanErr = scanErr
			}
		}(wsClient)
		return nil
	}
	if opts.AuthorityVerifier == nil && !wsOpts.receiptEffects.enabled {
		if err := startUpstream(); err != nil {
			if sessionExit.inProgress() && errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}

	settleHandshakeFailure := func(decision httpInputDecision) {
		warnTransportAdmission(safeLogW, wsOpts, decision.admission, "upstream_handshake_failed")
		decision.Outcome.settle(safeLogW, wsOpts, "error", -1, "upstream_handshake_failed")
	}

	refuseTaskRelease := func(frame MCPFrame, decision httpInputDecision, refusal string) {
		outcome := decision.Outcome
		intent := outcome.Receipt
		intent.Layer = mcpReceiptLayerTaint
		intent.TaintDecision = config.ActionBlock
		intent.TaintDecisionReason = decision.taskTaint.recordTaskReleaseRefusal(refusal)
		denialAudit := mcpTaintDenialAudit()
		block := inputMCPDenial(wsOpts, denialAudit, &BlockedRequest{
			ID: frame.ID, IsNotification: isRPCNotification(frame.ID),
			ErrorCode: -32002, ErrorMessage: "pipelock: " + refusal,
		})
		if wsOpts.receiptEffects.enabled {
			block.v3Evidence = mcpInputDenialEvidence(wsOpts, frame, denialAudit, receipt.EmitOpts{
				Layer: intent.Layer, Pattern: intent.TaintDecisionReason, Severity: taintReceiptSeverity(decision.taskTaint),
			})
		}
		if wErr := deliverMCPInputResult(wsOpts, *block, localClientOut); wErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send task refusal: %v\n", wErr)
		}
		outcome.Receipt = intent
		outcome.settle(safeLogW, wsOpts, mcpOutcomeStatusBlocked, -1, intent.TaintDecisionReason)
	}

	// Stdin -> upstream loop (runs on main goroutine).
	var stdinErr error
	var admission receipt.EmitOpts
	finishWarnings := func() {}
	settleMessage := func() {
		finishWarnings()
		admission.ReleaseNativeAdmission()
	}
	defer settleMessage()
	for {
		settleMessage()
		admission = receipt.EmitOpts{}
		finishWarnings = func() {}
		msg, readErr := readMCPInputMessage(innerCtx, clientIn, clientReader)
		if readErr != nil {
			if innerCtx.Err() == nil && !errors.Is(readErr, io.EOF) &&
				(!sessionExit.inProgress() || !isSessionExitCloseErr(readErr)) {
				stdinErr = fmt.Errorf("reading stdin: %w", readErr)
			}
			break
		}

		// Parse the inbound frame once per message; every gate below reads
		// ID / Method / tool fields from this frame instead of re-parsing.
		frame := ParseMCPFrame(msg)

		select {
		case <-innerCtx.Done():
			// Upstream closed or external cancellation.
			if wsClient != nil {
				_ = wsClient.Close()
			}
			wg.Wait()
			if streamAdmission.NativeLease.Stopping() {
				return ael.ErrCapacity
			}
			if stdinErr != nil {
				return stdinErr
			}
			if lastScanErr != nil {
				return lastScanErr
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			return nil
		default:
		}

		var admissionErr error
		admission, admissionErr = streamAdmission.ReserveNativeChild(nativeMCPRequestRecords)
		if admissionErr == nil {
			admission, admissionErr = admission.ReserveNativeTerminal()
		}
		if admissionErr != nil {
			writeNativeAdmissionDenial(wsOpts, safeLogW, localClientOut, frame, admissionErr)
			if errors.Is(admissionErr, ael.ErrCapacity) {
				continue
			}
			return admissionErr
		}
		inputOpts := wsOpts
		inputOpts.nativeAdmission = admission
		inputOpts.WarnContext, finishWarnings = inputOpts.nativeWarningContext(innerCtx, admission)

		// Kill switch: deny all messages when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(msg); d.Active {
				denialAudit := mcpKillMcpInputDenialAudit()
				batchResp := refuseKillSwitchRequest(inputOpts, safeLogW, frame, d)
				if batchResp != nil {
					if wErr := writeMCPInputDenial(wsOpts, denialAudit, localClientOut, frame, batchResp); wErr != nil {
						_, _ = fmt.Fprintf(safeLogW, "pipelock: stdout write error: %v\n", wErr)
					}
					continue
				}
				if d.IsNotification {
					dropMCPInputNotification(inputOpts, safeLogW, denialAudit, frame)
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				resp := killswitch.ErrorResponse(frame.ID, d.Message)
				if wErr := writeMCPInputDenial(wsOpts, denialAudit, localClientOut, frame, resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: stdout write error: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning: DLP, injection, policy, chain detection.
		decision := scanHTTPInputDecision(msg, safeLogW, sessionKey, sessionKey, inputOpts)
		if decision.Synthetic != nil {
			if err := deliverMCPSynthetic(decision.Synthetic, localClientOut); err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: synthetic response write error: %v\n", err)
			}
			continue
		}

		if decision.Blocked != nil {
			if wErr := deliverMCPInputResult(wsOpts, *decision.Blocked, localClientOut); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send input result: %v\n", wErr)
			}
			continue
		}

		if !wsOpts.receiptEffects.enabled {
			if err := startUpstream(); err != nil {
				settleHandshakeFailure(decision)
				if sessionExit.inProgress() && errors.Is(err, context.Canceled) {
					break
				}
				stdinErr = err
				break
			}
		}

		if refusal := mcpTaskReleaseRefusal(wsOpts, decision.taskFrame, decision.taskTaint, false); refusal != "" {
			refuseTaskRelease(frame, decision, refusal)
			continue
		}

		// Track request ID before forwarding for confused deputy protection.
		// Only track requests (have "method"), not client responses to
		// server-initiated calls, to prevent tracker pollution.
		var registration *requestRegistration
		awaitReply := isTrackableRequest(msg, frame.ID)
		if awaitReply {
			var refusal string
			var trackingErr error
			registration, refusal, trackingErr = registerWSTaskOutcome(safeLogW, inputOpts, tracker, frame, decision)
			if trackingErr != nil {
				decision.Outcome.settle(safeLogW, inputOpts, mcpOutcomeStatusBlocked, -1, "request_tracking_failed")
				writeNativeAdmissionDenial(inputOpts, safeLogW, localClientOut, frame, trackingErr)
				continue
			}
			if refusal != "" {
				refuseTaskRelease(frame, decision, refusal)
				continue
			}
		}

		effect, err := inputOpts.startV3Send(innerCtx, frame, decision.v3Evidence)
		if err != nil {
			tracker.removeOwnedOutcome(frame.ID, registration)
			decision.Outcome.settle(safeLogW, inputOpts, mcpOutcomeStatusBlocked, -1, "receipt_admission_failed")
			logMCPV3Error(safeLogW, err)
			_ = inputOpts.writeV3SendDenial(safeLogW, transport.NewStdioWriter(safeClientOut), frame, effect, err)
			continue
		}
		if innerCtx.Err() != nil {
			inputOpts.finishV3Send(innerCtx, safeLogW, effect, false)
			break
		}

		// With authority enabled, delay the upstream TCP/WebSocket handshake
		// until the first message has passed every existing gate plus the grant
		// check in scanHTTPInputDecision.
		if err := startUpstream(); err != nil {
			inputOpts.finishV3Send(innerCtx, safeLogW, effect, false)
			settleHandshakeFailure(decision)
			if sessionExit.inProgress() && errors.Is(err, context.Canceled) {
				break
			}
			stdinErr = err
			break
		}

		var bindErr error
		if awaitReply {
			bindErr = inputOpts.bindV3Send(effect)
			if bindErr == nil && inputOpts.afterWSBindForTest != nil {
				inputOpts.afterWSBindForTest()
			}
		}
		if bindErr != nil || innerCtx.Err() != nil {
			inputOpts.finishV3Send(innerCtx, safeLogW, effect, false)
			if effect == nil {
				tracker.removeOwnedOutcome(frame.ID, registration)
				continue
			}
			outcome, tracked := tracker.takeOwnedOutcome(frame.ID, registration)
			if bindErr != nil {
				if !tracked {
					outcome = decision.Outcome
				}
				outcome.settle(safeLogW, inputOpts, mcpOutcomeStatusBlocked, -1, "request_tracking_failed")
				writeNativeAdmissionDenial(inputOpts, safeLogW, localClientOut, frame, bindErr)
			} else {
				if tracked {
					outcome.settle(safeLogW, inputOpts, "cancelled", -1, httpstream.Cancelled)
				}
				break
			}
			continue
		}

		// Forward to upstream.
		writeErr := wsClient.WriteMessage(decision.ForwardMessage)
		if writeErr != nil {
			inputOpts.finishV3Send(innerCtx, safeLogW, effect, true)
			upstreamWriteFailed = ctx.Err() == nil
			tracker.removeOwnedOutcome(frame.ID, registration)
			warnTransportAdmission(safeLogW, wsOpts, decision.admission, mcpUpstreamWriteFailed)
			decision.Outcome.settle(safeLogW, wsOpts, "error", -1, mcpUpstreamWriteFailed)
			stdinErr = fmt.Errorf("upstream write: %w", writeErr)
			break
		}
		if effect != nil && !awaitReply {
			logMCPV3Error(safeLogW, confirmMCPV3Effect(innerCtx, effect.token, true))
		}
		if isRPCNotification(frame.ID) {
			decision.Outcome.settle(safeLogW, wsOpts, "forwarded", -1, "notification_forwarded")
		}
		commitMCPToolCall(baselineMetricsRecorder(wsOpts, rec), mcpFrameBaselineIdentity(frame))
	}

	// Keep the upstream open for replies already admitted when stdin ends
	// during a capacity stop. The capacity cutoff bounds the wait.
	if streamAdmission.NativeLease.Stopping() && tracker.HasPending() {
		<-innerCtx.Done()
	}

	// Close the WS connection to unblock ForwardScanned's ReadMessage. The
	// blocked read returns net.ErrClosed ("use of closed network connection"),
	// which ForwardScanned treats as a clean stream end via
	// wsutil.IsExpectedCloseErr, so it exits without a spurious error.
	cancel()
	if wsClient != nil {
		_ = wsClient.Close()
	}
	wg.Wait()

	if streamAdmission.NativeLease.Stopping() {
		return ael.ErrCapacity
	}
	if err := context.Cause(replyCtx); errors.Is(err, errMCPV3ReplyAdmission) {
		return err
	}
	if stdinErr != nil {
		return stdinErr
	}
	if lastScanErr != nil {
		return lastScanErr
	}
	return nil
}

// a2aCardURLForWSUpstream maps a WebSocket endpoint to the equivalent HTTP
// origin used by Agent Card signature key scopes. The path remains part of the
// drift key, while ws and wss carry the same authority as http and https.
func a2aCardURLForWSUpstream(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	switch strings.ToLower(u.Scheme) {
	case "ws":
		u.Scheme = "http"
	case "wss":
		u.Scheme = "https"
	}
	return u.String()
}

// Registering can settle an evicted outcome and invoke receipt observers.
// Check the current task permission after those observers have returned.
func registerWSTaskOutcome(logW io.Writer, opts MCPProxyOpts, tracker *RequestTracker, frame MCPFrame, decision httpInputDecision) (*requestRegistration, string, error) {
	outcome := decision.Outcome
	outcome.Method = frame.Method
	outcome.Receipt = outcome.Receipt.InheritAdmission(opts.nativeAdmission)
	registration, err := trackMCPAdmittedOutcome(logW, opts, tracker, frame.ID, outcome, false)
	if err != nil {
		return nil, "", err
	}
	refusal := mcpTaskReleaseRefusal(opts, decision.taskFrame, decision.taskTaint, false)
	if refusal != "" {
		tracker.removeOwnedOutcome(frame.ID, registration)
	}
	return registration, refusal, nil
}
