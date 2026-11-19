// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	contractruntime "github.com/luckyPipewrench/pipelock/internal/contract/runtime"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

func emitRequestScopedTimeout(
	respReader transport.MessageReader,
	writer transport.MessageWriter,
	logW io.Writer,
	tracker *RequestTracker,
	id json.RawMessage,
	logMessage string,
	opts MCPProxyOpts,
) {
	if c, ok := respReader.(io.Closer); ok {
		_ = c.Close()
	}
	if len(id) != 0 {
		outcome, ok := consumeTrackedRequestOutcome(tracker, id)
		if ok {
			defer outcome.releaseNativeLease()
			resp := timeoutErrorResponse(id)
			if wErr := writer.WriteMessage(resp); wErr != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: failed to send timeout response: %v\n", wErr)
			}
			emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, outcome.Receipt, "error", int64(len(resp)), "response_timeout", opts.requireReceipts())
		}
	}
	_, _ = fmt.Fprintln(logW, logMessage)
}

func emitTrackedTerminalOutcome(logW io.Writer, tracker *RequestTracker, id json.RawMessage, resp []byte, reason string, opts MCPProxyOpts) {
	outcome, ok := consumeTrackedRequestOutcome(tracker, id)
	if !ok {
		return
	}
	defer outcome.releaseNativeLease()
	emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, outcome.Receipt, mcpResponseStatus(resp), int64(len(resp)), reason, opts.requireReceipts())
}

// emitContractRefusedOutcome writes the blocked outcome for a call the live
// upstream contract refused. Notifications are never tracked, so their caller
// passes the outcome from the input decision directly.
func emitContractRefusedOutcome(logW io.Writer, outcome TrackedRequestOutcome, gate mcpContractGateOutput, reason string, bytesTransferred int64, opts MCPProxyOpts) {
	defer outcome.releaseNativeLease()
	receiptOpts := mcpWithContractReceipt(outcome.Receipt, gate)
	receiptOpts.Layer = mcpContractReceiptLayer
	emitMCPBlockedOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, receiptOpts, bytesTransferred, reason, opts.requireReceipts())
}

func emitTrackedIncompleteOutcome(logW io.Writer, tracker *RequestTracker, id json.RawMessage, reason string, opts MCPProxyOpts) {
	outcome, ok := consumeTrackedRequestOutcome(tracker, id)
	if !ok {
		return
	}
	defer outcome.releaseNativeLease()
	emitMCPOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, outcome.Receipt, "incomplete", -1, reason, opts.requireReceipts())
}

func consumeTrackedRequestOutcome(tracker *RequestTracker, id json.RawMessage) (TrackedRequestOutcome, bool) {
	if tracker == nil {
		return TrackedRequestOutcome{}, true
	}
	return tracker.Consume(id)
}

type mcpInputReadResult struct {
	message []byte
	err     error
}

// readMCPInputMessage lets a session-bound HTTP bridge return when its parent
// exits even when a caller supplied a Reader that cannot be closed. Closable
// inputs use the direct read path: newSessionBoundContext closes them on exit.
// A non-closable input leaves at most its single blocked Read behind; its result
// channel is buffered, so releasing that reader cannot strand a goroutine after
// the bridge has already returned.
func readMCPInputMessage(ctx context.Context, clientIn io.Reader, reader transport.MessageReader) ([]byte, error) {
	if _, closable := clientIn.(io.Closer); closable {
		return reader.ReadMessage()
	}

	result := make(chan mcpInputReadResult, 1)
	go func() {
		message, err := reader.ReadMessage()
		result <- mcpInputReadResult{message: message, err: err}
	}()

	select {
	case result := <-result:
		return result.message, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// RunHTTPProxy bridges stdio (client) to an upstream HTTP MCP server with
// bidirectional scanning. Reads JSON-RPC from clientIn, POSTs to upstreamURL,
// scans responses via ForwardScanned, writes to clientOut.
// When opts.Store is non-nil, a per-invocation session recorder is created and
// used for adaptive enforcement signal recording across both input and response
// scanning.
func RunHTTPProxy(
	ctx context.Context,
	clientIn io.Reader,
	clientOut io.Writer,
	logW io.Writer,
	upstreamURL string,
	extraHeaders http.Header,
	opts MCPProxyOpts,
) error {
	// Capture before validating the upstream to narrow the time startup work can
	// hide a parent death. This cannot close the earlier launcher-to-first-
	// syscall race; that needs a harness-owned lifetime primitive.
	startupParentWatch := parentWatchOpts{startPPID: os.Getppid()}
	safeClientOut := &syncWriter{w: clientOut}
	safeLogW := &syncWriter{w: logW}
	ctx, cancel, sessionExit := newSessionBoundContext(ctx, startupParentWatch, clientIn, safeLogW, opts.sessionExitForTest)
	defer cancel()
	defer opts.closeNativeInputOnStop(clientIn)()

	// Set transport for capture records if not already set by caller.
	if opts.Transport == "" {
		opts.Transport = "mcp_http_upstream"
	}
	if opts.ContractServer == "" {
		opts.ContractServer = mcpContractServerFromUpstream(upstreamURL)
	}
	if opts.AuthorityDestination == "" {
		opts.AuthorityDestination = upstreamURL
	}
	if opts.A2ACardURL == "" {
		opts.A2ACardURL = upstreamURL
	}
	if opts.A2ACardAuthFingerprint == "" {
		opts.A2ACardAuthFingerprint = CardCacheKeyFromRequest("", extraHeaders.Get("Authorization")).authFingerprint
	}
	opts.TaintExternalSource = true

	if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
		dropMCPDenial(opts, mcpStartupDenialAudit(mcpListenerContractEvalDenialAudit()), "startup")
		return fmt.Errorf("contract upstream evaluation: %w", gateErr)
	} else if gate.Verdict == config.ActionBlock {
		dropMCPDenial(opts, mcpStartupDenialAudit(mcpUpstreamGateDenialAudit(gate)), "startup")
		return fmt.Errorf("contract upstream denied: %s", mcpContractBlockReason(gate))
	}

	// Per-invocation adaptive enforcement recorder. Mint the invocation
	// key once so it can also feed scanHTTPInputDecision below, keeping
	// CEE state and audit correlation scoped to this RunHTTPProxy call
	// instead of a shared "default" bucket across unrelated invocations.
	invocationKey := session.NextInvocationKey("mcp-http")
	var rec session.Recorder
	if opts.Store != nil {
		rec = opts.Store.GetOrCreate(invocationKey)
		if rec == nil {
			dropMCPDenial(opts, mcpStartupDenialAudit(mcpListenerCapacityDenialAudit()), "startup")
			return session.ErrCapacity
		}
		defer opts.Store.Delete(invocationKey)
		opts.taskSubject = invocationKey
		session.BindTaskSubject(rec, opts.taskSubject)
	}
	defer recordMCPBaselineSample(opts, rec)

	httpClient := transport.NewHTTPClientWithDialer(upstreamURL, extraHeaders, opts.DialContext)
	httpClient.ResponseKeyValidator = jsonrpc.ValidateMessageKeys
	var upstreamMu sync.Mutex

	// Tool scanning baseline for this session. Clone the caller's ToolCfg
	// with a fresh per-session baseline so drift detection is scoped to
	// this invocation.
	toolCfg := opts.toolCfg()
	var fwdToolCfg *tools.ToolScanConfig
	if toolCfg != nil {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:                tools.NewToolBaseline(),
			Action:                  toolCfg.Action,
			DetectDrift:             toolCfg.DetectDrift,
			NewToolAdmission:        toolCfg.NewToolAdmission,
			ExtraPoison:             toolCfg.ExtraPoison,
			BindingUnknownAction:    toolCfg.BindingUnknownAction,
			BindingNoBaselineAction: toolCfg.BindingNoBaselineAction,
			CredentialAcks:          toolCfg.CredentialAcks,
			Now:                     toolCfg.Now,
		}
	}

	if fwdToolCfg == nil {
		fwdToolCfg = &tools.ToolScanConfig{
			Baseline:            tools.NewToolBaseline(),
			Action:              config.ActionBlock,
			HeaderContractsOnly: true,
			CredentialAcks:      nil, // The caller supplied no tool-scanning configuration.
		}
	}
	contractState := &mcpListenerClientState{baseline: fwdToolCfg.Baseline}

	// Request tracker for confused deputy protection.
	tracker := NewRequestTracker()
	// The background GET stream carries server requests and notifications. A
	// JSON-RPC result/error on that channel is unsolicited even if it copies an
	// ID currently outstanding on the POST response path.
	getResponseTracker := NewStrictRequestTracker()

	// Session-scoped opts: override Rec and ToolCfg from the caller's opts.
	fwdOpts := opts
	fwdOpts.Rec = rec
	fwdOpts.ToolCfg = fwdToolCfg
	fwdOpts.ToolCfgFn = nil
	if toolCfg == nil {
		fwdOpts.ToolCfg = nil
	}
	fwdOpts.WarnContext = ctx
	fwdOpts.sessionExit = sessionExit
	resolverRuntime := newDeferResolverRuntime(ctx)
	fwdOpts.DeferResolverRuntime = resolverRuntime
	killWatchCtx, stopKillWatch := context.WithCancel(ctx)
	go watchDeferredKillSwitch(killWatchCtx, fwdOpts.KillSwitch, fwdOpts.deferManager())
	capacityDeferralsDone := make(chan struct{})
	go func() {
		defer close(capacityDeferralsDone)
		watchCapacityDeferrals(killWatchCtx, fwdOpts)
	}()
	defer func() {
		stopKillWatch()
		resolverRuntime.Cancel()
		if manager := fwdOpts.deferManager(); manager != nil {
			manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
		}
		resolverRuntime.Wait()
		<-capacityDeferralsDone
	}()

	bridgeHeaders := &mcpBridgeHeaders{client: httpClient, state: contractState, opts: fwdOpts, log: safeLogW}
	bridgeHeaders.opts.ToolCfg = fwdToolCfg

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var getStreamOnce sync.Once
	var lastScanErr error
	var admission receipt.EmitOpts
	finishWarnings := func() {}
	stopCapacity := func() {}
	settleAdmission := func() {
		finishWarnings()
		stopCapacity()
		admission.ReleaseNativeAdmission()
	}
	defer settleAdmission()

	for {
		settleAdmission()
		finishWarnings = func() {}
		stopCapacity = func() {}
		admission = receipt.EmitOpts{}
		msg, err := readMCPInputMessage(ctx, clientIn, clientReader)
		if err != nil {
			if errors.Is(err, io.EOF) || (sessionExit.inProgress() && (isSessionExitCloseErr(err) || errors.Is(err, context.Canceled))) {
				break
			}
			lastScanErr = fmt.Errorf("reading stdin: %w", err)
			break
		}
		var deferredGeneration uint64
		if fwdOpts.KillSwitch != nil {
			deferredGeneration = fwdOpts.KillSwitch.DeferredGeneration()
		}

		// Parse the inbound frame once per message. Kill switch, request
		// tracking, and upstream-error responses all read frame.ID
		// instead of re-parsing.
		fwdOpts := fwdOpts // Each deferred closure retains this message's policy snapshot.
		frame := ParseMCPFrame(msg)
		var admissionErr error
		admission, admissionErr = fwdOpts.admitNativeRequest()
		if admissionErr != nil {
			writeNativeAdmissionDenial(fwdOpts, safeLogW, safeClientOut, frame.ID, admissionErr)
			lastScanErr = admissionErr
			break
		}
		fwdOpts.nativeAdmission = admission
		fwdOpts.WarnContext, finishWarnings = fwdOpts.nativeWarningContext(fwdOpts.warnContext(), admission)
		if taintCfg := fwdOpts.TaintCfg; fwdOpts.TaintCfgFn != nil || (taintCfg != nil && taintCfg.Enabled) {
			fwdOpts.deferBestEffortTaskReceipt = true
		}
		fwdOpts.validateToolHeaders = bridgeHeaders.version(msg) >= currentMCPVersion
		if fwdOpts.validateToolHeaders {
			fwdOpts.ToolCfg = fwdToolCfg
		}
		var denialAudit mcpDenialAudit

		if err := ctx.Err(); err != nil {
			lastScanErr = err
			break
		}

		// Kill switch: deny all messages when active.
		if opts.KillSwitch != nil {
			if d := opts.KillSwitch.IsActiveMCP(msg); d.Active {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditKillSwitch, mcpKillSwitchReason, audit.BlockClassProtective)
				if manager := fwdOpts.deferManager(); manager != nil {
					manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
				}
				batchResp := refuseKillSwitchRequest(fwdOpts, safeLogW, frame, d)
				if batchResp != nil {
					if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, batchResp); wErr != nil {
						_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
					}
					continue
				}
				if d.IsNotification {
					dropMCPDenial(fwdOpts, denialAudit, "input")
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				rpcID := frame.ID
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, resp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
				}
				continue
			}
		}

		// Input scanning - call ScanRequest and CheckRequest directly.
		// The sequential (non-concurrent) architecture means no channel needed.
		decision := scanHTTPInputDecision(msg, safeLogW, invocationKey, invocationKey, fwdOpts)
		if decision.Synthetic != nil {
			if err := deliverMCPSynthetic(decision.Synthetic, safeClientOut); err != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: synthetic response write error: %v\n", err)
			}
			continue
		}

		if decision.Blocked != nil {
			if wErr := deliverMCPInputResult(fwdOpts, *decision.Blocked, safeClientOut); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send input result: %v\n", wErr)
			}
			continue
		}

		if decision.Deferred != nil {
			manager := fwdOpts.deferManager()
			if manager == nil || !manager.Enabled() {
				denialAudit = mcpDeferDisabledDenialAudit()
				if decision.Deferred.IsNotification {
					dropMCPDenial(fwdOpts, denialAudit, "input")
				}
				resp := blockRequestResponse(BlockedRequest{
					ID:             decision.Deferred.ID,
					IsNotification: decision.Deferred.IsNotification,
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: defer is disabled",
				})
				if !decision.Deferred.IsNotification {
					_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, resp)
				}
				continue
			}
			deferredReq := decision.Deferred
			// gateBlock carries a release-time upstream gate denial from
			// Prepare to Resolve for this hold.
			var gateBlock *BlockedRequest
			var gateAudit mcpDenialAudit
			var releaseHeaders http.Header
			var headerContractErr error
			receiptSettle := &deferredReceiptSettlement{}
			var terminalSlot mcpDeferredTerminal
			// A receipt or journal failure can downgrade a prepared allow to
			// deny. Release its upstream write lock and send claim before the
			// finalizer's synchronous audit sinks or downstream delivery can
			// block unrelated upstream work. OnceFunc also makes the manager's
			// deferred cleanup safe after this early denial cleanup.
			var finishDeniedRelease func()
			heldOpts, finishHeldAdmission, holdErr := fwdOpts.splitDeferredAdmission()
			heldAction := deferred.HeldAction{
				DeferID:       deferredReq.DeferID,
				ActionID:      deferredReq.DeferID,
				ShardIndex:    deferredReq.ShardIndex,
				ShardSelected: deferredReq.ShardSelected,
				Target:        deferredReq.ToolName,
				Reason:        deferredReq.Reason,
				Surface:       opts.Transport,
				Method:        deferredReq.Method,
				SizeBytes:     len(deferredReq.ForwardMessage),
				RulePolicy:    deferredReq.ResolutionPolicy,
				Payload:       append([]byte(nil), deferredReq.ForwardMessage...),
				ArgDigest:     deferredReq.ArgDigest,
				Authority: deferred.AuthoritySnapshot{
					SessionID:         deferredReq.SessionID,
					SessionIDOriginal: deferredReq.SessionIDOriginal,
				},
				BeforeAllow: func() (func(), bool) {
					return deferredReleasePrecheck(heldOpts, deferredGeneration)
				},
				// Prepare settles the final decision before the manager
				// journals it, so the journal and the receipt agree. On an
				// allow it returns holding upstreamMu and the kill-switch
				// claim; the manager releases both with defer after Resolve
				// returns or panics. It runs on the resolving goroutine
				// immediately before Resolve, which reads gateBlock.
				Prepare: func(res deferred.Resolution) (deferred.Resolution, func()) {
					if res.FinalDecision == config.ActionAllow {
						if authErr := authorizeMCP(ctx, deferredReq.authorityRef, deferredReq.authorityCarrierErr, deferredReq.authorityFrame, fwdOpts); authErr != nil {
							res.FinalDecision = config.ActionBlock
							res.ResolutionSource = deferred.SourceAuthority
							res.Reason = "authority verification failed"
						}
					}
					if res.ResolutionSource == deferred.SourceKillSwitch {
						markDeferredKillSwitch(&res)
					}
					// Rerun the live upstream gate the ordinary forward path
					// applies before SendMessage; the upstream may have been
					// locked while the call was held.
					if res.FinalDecision == config.ActionAllow {
						gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, fwdOpts)
						switch {
						case gateErr != nil:
							gateAudit = mcpListenerContractEvalDenialAudit()
							_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
							br := mcpContractBlockRequest(deferredReq.ID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed")
							gateBlock = &br
						case gate.Verdict == config.ActionBlock && mcpContractBlockReason(gate) == blockreason.KillSwitchActive:
							markDeferredKillSwitch(&res)
						case gate.Verdict == config.ActionBlock:
							_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
							gateAudit = mcpUpstreamGateDenialAudit(gate)
							br := mcpContractBlockRequest(deferredReq.ID, gate, "pipelock: upstream URL blocked by live-lock contract")
							gateBlock = &br
						}
						if gateBlock != nil {
							res.FinalDecision = config.ActionBlock
							res.ResolutionSource = deferred.SourceUpstreamContract
							res.Reason = deferredUpstreamContractReason
						}
					}
					if res.FinalDecision != config.ActionAllow {
						return res, nil
					}

					releaseHeaders, headerContractErr = bridgeHeaders.prepareForRelease(ctx, deferredReq.ForwardMessage, deferredGeneration)
					if headerContractErr != nil {
						// Discovery can end because a kill interrupted its wait, or
						// fail on its own while a kill invalidates this hold. Either
						// way the kill-switch cancellation owns the final reason.
						if ks := fwdOpts.KillSwitch; ks != nil && (ks.DeferredGeneration() != deferredGeneration || ks.IsActive()) {
							markDeferredKillSwitch(&res)
							return res, nil
						}
						// The resolution receipt closes the held action, as for the
						// live upstream gate above. The hold wrote a defer receipt,
						// not an intent, so an outcome under its ID would read as
						// "outcome without matching intent" to completeness checks.
						_, _ = fmt.Fprintf(safeLogW, "pipelock: header contract refused deferred call %s: %q\n", deferredReq.DeferID, headerContractErr.Error())
						res.FinalDecision = config.ActionBlock
						res.ResolutionSource = deferred.SourceUpstreamContract
						var message string
						gateAudit, message, res.Reason = bridgeHeaderRefusal(headerContractErr)
						br := BlockedRequest{ID: deferredReq.ID, ErrorCode: -32020, ErrorMessage: message}
						gateBlock = &br
						return res, nil
					}
					// Irreversible release boundary. Take the upstream lock
					// first so no wait for another send sits between the
					// kill-switch claim and SendMessage; see
					// claimDeferredRelease for the ordering argument.
					prepared, finish := lockAndClaimDeferredRelease(&upstreamMu, heldOpts, deferredGeneration, res)
					if prepared.FinalDecision == config.ActionAllow {
						if reason := mcpTaskReleaseRefusal(fwdOpts, deferredReq.authorityFrame, deferredReq.taskTaint, false); reason != "" {
							prepared.FinalDecision = config.ActionBlock
							prepared.Reason = reason
							gateAudit = mcpTaintDenialAudit()
							gateBlock = &BlockedRequest{ID: deferredReq.ID, ErrorCode: -32002, ErrorMessage: "pipelock: " + reason}
						}
					}
					if finish != nil {
						finish = sync.OnceFunc(finish)
						finishDeniedRelease = finish
					}
					prepared = receiptSettle.probeAllow(heldOpts, prepared)
					return prepared, finish
				},
				// The release receipt is written while the journal shows the
				// release as pending: the allow first, then a corrective block
				// if the journal cannot record the allow as final.
				AfterJournal: func(res deferred.Resolution) error {
					return receiptSettle.commitAllow(heldOpts, safeLogW, res)
				},
				Resolve: func(res deferred.Resolution) {
					defer finishHeldAdmission()
					denialOpts := heldOpts
					denialOpts.denialTerminal = &terminalSlot
					denialAudit := mcpDeferredDenialAudit(res)
					if gateBlock != nil {
						denialAudit = gateAudit
					}
					authorityDenied := res.ResolutionSource == deferred.SourceAuthority
					if emitErr := receiptSettle.ensure(heldOpts, safeLogW, res); emitErr != nil {
						if finishDeniedRelease != nil {
							finishDeniedRelease()
						}
						if res.FinalDecision == config.ActionAllow {
							denialAudit = mcpReceiptMcpInputDenialAudit()
						}
						if deferredReq.IsNotification {
							dropMCPDenial(denialOpts, denialAudit, "input")
						}
						if !deferredReq.IsNotification {
							_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32007,
								ErrorMessage: "pipelock: receipt emission failed",
							}))
						}
						return
					}
					switch res.FinalDecision {
					case config.ActionAllow:
						// upstreamMu is held by Prepare's release claim.
						if isRequest(deferredReq.ForwardMessage) {
							outcome := TrackedRequestOutcome{Receipt: heldOpts.nativeAdmission, Method: deferredReq.Method}
							if err := trackNativeOutcome(tracker, deferredReq.ID, outcome); err != nil {
								if finishDeniedRelease != nil {
									finishDeniedRelease()
								}
								writeNativeAdmissionDenial(heldOpts, safeLogW, safeClientOut, deferredReq.ID, err)
								return
							}
						}
						releaseCtx, stopRelease := httpstream.WithCapacityGrace(heldOpts.warnContext(), nil, heldOpts.nativeAdmission.NativeLease, heldOpts.shutdownGrace())
						defer stopRelease()
						releaseOpts := heldOpts
						releaseOpts.WarnContext = releaseCtx
						respReader, sendErr := httpClient.SendMessageWithOptions(releaseCtx, deferredReq.ForwardMessage, transport.HTTPMessageOptions{Headers: releaseHeaders})
						if sendErr != nil {
							if errors.Is(context.Cause(releaseCtx), ael.ErrCapacity) {
								emitTrackedStreamError(releaseCtx, safeLogW, tracker, deferredReq.ID, releaseOpts, ael.ErrCapacity)
								return
							}
							errResp := upstreamErrorResponse(deferredReq.ID, fmt.Errorf("upstream HTTP request failed"))
							if !deferredReq.IsNotification {
								_ = safeClientOut.WriteMessage(errResp)
							}
							emitTrackedTerminalOutcome(safeLogW, tracker, deferredReq.ID, errResp, "upstream_error", releaseOpts)
							return
						}
						if transport.IsStreamingResponse(respReader) {
							releaseOpts.nativeSSE = true
						}
						respReader = releaseOpts.withResponseTimeout(respReader)
						foundInjection, scanErr := ForwardScanned(respReader, safeClientOut, safeLogW, tracker, releaseOpts)
						if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(context.Cause(releaseCtx), ael.ErrCapacity) {
							emitTrackedStreamError(releaseCtx, safeLogW, tracker, deferredReq.ID, releaseOpts, ael.ErrCapacity)
						} else if errors.Is(scanErr, transport.ErrResponseTimeout) {
							emitRequestScopedTimeout(
								respReader,
								safeClientOut,
								safeLogW,
								tracker,
								deferredReq.ID,
								"pipelock: upstream response timeout on deferred request; failed request closed",
								releaseOpts,
							)
						} else if scanErr != nil {
							_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
							// Only an unanswered request gets a terminal error. A stream
							// can fail after its response already consumed the ID.
							if outcome, pending := consumeTrackedRequestOutcome(tracker, deferredReq.ID); pending {
								defer outcome.releaseNativeLease()
								errResp := upstreamErrorResponse(deferredReq.ID, fmt.Errorf("upstream HTTP response failed"))
								if !deferredReq.IsNotification {
									_ = safeClientOut.WriteMessage(errResp)
								}
								emitMCPOutcomeReceipt(fwdOpts.receiptEmitter(), fwdOpts.v2ReceiptEmitter(), fwdOpts.ReceiptGroup, safeLogW, outcome.Receipt, "error", int64(len(errResp)), "scan_error", fwdOpts.requireReceipts())
							}
						} else if !foundInjection {
							baselineIdentity := deferredReq.BaselineIdentity
							if baselineIdentity == "" {
								baselineIdentity = mcpFrameBaselineIdentity(ParseMCPFrame(deferredReq.ForwardMessage))
							}
							commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), baselineIdentity)
						}
					default:
						if finishDeniedRelease != nil {
							finishDeniedRelease()
						}
						if res.ResolutionSource == deferred.SourceKillSwitch {
							denialAudit = mcpInputGateBlockAudit(scanner.AuditKillSwitch, mcpKillSwitchReason, audit.BlockClassProtective)
							_, _ = fmt.Fprintf(safeLogW, "pipelock: deferred call %s cancelled by kill switch\n", res.DeferID)
						}
						if deferredReq.IsNotification {
							dropMCPDenial(denialOpts, denialAudit, "input")
						}
						if !deferredReq.IsNotification {
							if authorityDenied {
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, blockRequestResponse(*authorityBlockedRequest(deferredReq.authorityFrame)))
								return
							}
							if gateBlock != nil {
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, blockRequestResponse(*gateBlock))
								return
							}
							if res.ResolutionSource == deferred.SourceKillSwitch {
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, killswitch.ErrorResponse(deferredReq.ID, deferredKillSwitchMessage(fwdOpts)))
								return
							}
							_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32002,
								ErrorMessage: "pipelock: deferred action denied",
							}))
						}
					}
				},
			}
			if holdErr == nil {
				holdErr = manager.Hold(heldAction)
			}
			if holdErr == nil && heldOpts.nativeAdmission.NativeLease.Stopping() {
				_ = manager.Resolve(deferredReq.DeferID, config.ActionBlock, deferred.SourceCancel)
			}
			if holdErr != nil {
				finishHeldAdmission()
				errorMessage, emitErr := emitHoldFailureResolution(fwdOpts, safeLogW, holdErr, holdFailureResolution{
					DeferID:       deferredReq.DeferID,
					ShardIndex:    deferredReq.ShardIndex,
					ShardSelected: deferredReq.ShardSelected,
					Authority: deferred.AuthoritySnapshot{
						SessionID:         deferredReq.SessionID,
						SessionIDOriginal: deferredReq.SessionIDOriginal,
					},
					Policy: manager.Policy(),
					Target: deferredReq.ToolName,
					Method: deferredReq.Method,
					Reason: deferredReq.Reason,
				})
				logHoldFailureReceiptGap(safeLogW, deferredReq.DeferID, emitErr)
				denialAudit = mcpDeferHoldDenialAudit()
				if deferredReq.IsNotification {
					dropMCPDenial(fwdOpts, denialAudit, "input")
				}
				if !deferredReq.IsNotification {
					_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, blockRequestResponse(BlockedRequest{
						ID:           deferredReq.ID,
						ErrorCode:    -32002,
						ErrorMessage: errorMessage,
					}))
				}
			} else if held, ok := manager.Held(deferredReq.DeferID); ok && deferredReq.ResolverProfileName != "" {
				maybeStartDeferApprovalResolver(resolverRuntime, manager, held, deferredReq.ResolverProfileName, deferredReq.ResolverProfile, deferredReq.Arguments, fwdOpts.IntegrityCfg, safeLogW)
			}
			continue
		}

		// Track request ID before sending to upstream for confused deputy protection.
		// Only track requests (have "method"), not client responses to
		// server-initiated calls, to prevent tracker pollution.
		if isTrackableRequest(msg, frame.ID) {
			outcome := decision.Outcome
			outcome.Receipt = outcome.Receipt.InheritAdmission(admission)
			outcome.Method = frame.Method
			if err := trackNativeOutcome(tracker, frame.ID, outcome); err != nil {
				emitMCPBlockedOutcomeReceipt(fwdOpts.receiptEmitter(), fwdOpts.v2ReceiptEmitter(), fwdOpts.ReceiptGroup, safeLogW, outcome.Receipt, -1, "request_tracking_failed", fwdOpts.requireReceipts())
				writeNativeAdmissionDenial(fwdOpts, safeLogW, safeClientOut, frame.ID, err)
				continue
			}
		}

		if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
			outcome := mcpLocalRefusedOutcome(tracker, frame.ID, decision)
			denialAudit = mcpListenerContractEvalDenialAudit()
			_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
			// Notifications have no id; JSON-RPC forbids responses to
			// them. Mirror the kill-switch and input-scan paths above.
			if isRPCNotification(frame.ID) {
				dropMCPDenial(fwdOpts, denialAudit, "input")
				emitContractRefusedOutcome(safeLogW, outcome, mcpContractGateOutput{}, mcpContractEvaluationFailedReason, 0, fwdOpts)
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed"))
			if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitContractRefusedOutcome(safeLogW, outcome, mcpContractGateOutput{}, mcpContractEvaluationFailedReason, int64(len(errResp)), fwdOpts)
			continue
		} else if gate.Verdict == config.ActionBlock {
			outcome := mcpLocalRefusedOutcome(tracker, frame.ID, decision)
			denialAudit = mcpUpstreamGateDenialAudit(gate)
			if gate.WinningSource == contractruntime.WinningSourceScanner {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream scanner denied: %s\n", gate.Reason)
			} else {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
			}
			if isRPCNotification(frame.ID) {
				dropMCPDenial(fwdOpts, denialAudit, "input")
				emitContractRefusedOutcome(safeLogW, outcome, gate, mcpContractDeniedReason, 0, fwdOpts)
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, gate, "pipelock: upstream URL blocked by live-lock contract"))
			if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitContractRefusedOutcome(safeLogW, outcome, gate, mcpContractDeniedReason, int64(len(errResp)), fwdOpts)
			continue
		}

		requestHeaders, headerErr := bridgeHeaders.prepare(ctx, decision.ForwardMessage)
		if headerErr != nil {
			outcome := mcpLocalRefusedOutcome(tracker, frame.ID, decision)
			_, _ = fmt.Fprintf(safeLogW, "pipelock: header contract refused: %q\n", headerErr.Error())
			denialAudit, message, reason := bridgeHeaderRefusal(headerErr)
			// Notifications are never tracked: close their intent from the input
			// decision, as the upstream gate above does.
			if isRPCNotification(frame.ID) {
				dropMCPDenial(fwdOpts, denialAudit, "input")
				emitBridgeHeaderContractRefusal(safeLogW, outcome, reason, fwdOpts)
				continue
			}
			response := blockRequestResponse(BlockedRequest{ID: frame.ID, ErrorCode: -32020, ErrorMessage: message})
			_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, response)
			emitBridgeHeaderContractRefusal(safeLogW, outcome, reason, fwdOpts)
			continue
		}

		unlockInventory := func() {}
		if frame.Method == "tools/list" {
			if lockErr := contractState.contractMu.Lock(ctx); lockErr != nil {
				emitPendingMCPInputReceipt(decision.pendingReceipt)
				// Only cancellation fails this wait. Close the request's
				// tracked outcome and leave through the shared shutdown path,
				// which settles other pending outcomes and ends the session.
				_, _ = fmt.Fprintf(safeLogW, "pipelock: inventory lock not acquired: %v\n", lockErr)
				emitTrackedIncompleteOutcome(safeLogW, tracker, frame.ID, "upstream_closed", fwdOpts)
				lastScanErr = lockErr
				break
			}
			var inventoryResolutions []string
			fwdOpts.toolInventoryResolution = func(decision string) { inventoryResolutions = append(inventoryResolutions, decision) }
			unlockInventory = sync.OnceFunc(func() {
				contractState.contractMu.Unlock()
				if manager := fwdOpts.deferManager(); manager != nil {
					for _, decision := range inventoryResolutions {
						manager.ResolveToolInventory(invocationKey, decision)
					}
				}
			})
		}
		// POST to upstream.
		var requestCtx context.Context
		requestCtx, stopCapacity = httpstream.WithCapacityGrace(ctx, nil, admission.NativeLease, fwdOpts.shutdownGrace())
		var taskRefusal string
		respReader, err := func() (transport.MessageReader, error) {
			upstreamMu.Lock()
			defer upstreamMu.Unlock()
			taskRefusal = mcpTaskReleaseRefusal(fwdOpts, decision.taskFrame, decision.taskTaint, false)
			if taskRefusal != "" {
				return nil, nil
			}
			return httpClient.SendMessageWithOptions(requestCtx, decision.ForwardMessage, transport.HTTPMessageOptions{Headers: requestHeaders})
		}()
		if taskRefusal != "" {
			unlockInventory()
			denialAudit := mcpTaintDenialAudit()
			outcome := mcpLocalRefusedOutcome(tracker, frame.ID, decision)
			var errResp []byte
			if isRPCNotification(frame.ID) {
				dropMCPDenial(fwdOpts, denialAudit, "input")
			} else {
				block := BlockedRequest{ID: frame.ID, ErrorCode: -32002, ErrorMessage: "pipelock: " + taskRefusal}
				errResp = blockRequestResponse(block)
				if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, errResp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send task refusal: %v\n", wErr)
				}
			}
			reason := decision.taskTaint.recordTaskReleaseRefusal(taskRefusal)
			outcome.Receipt.Layer = mcpReceiptLayerTaint
			outcome.Receipt.TaintDecision = config.ActionBlock
			outcome.Receipt.TaintDecisionReason = reason
			emitMCPBlockedOutcomeReceipt(fwdOpts.receiptEmitter(), fwdOpts.v2ReceiptEmitter(), fwdOpts.ReceiptGroup, safeLogW, outcome.Receipt, int64(len(errResp)), reason, fwdOpts.requireReceipts())
			outcome.releaseNativeLease()
			continue
		}
		// Keep receipt I/O out of the task-check-to-send interval.
		emitPendingMCPInputReceipt(decision.pendingReceipt)
		if err != nil {
			unlockInventory()
			if errors.Is(context.Cause(requestCtx), ael.ErrCapacity) {
				emitTrackedStreamError(requestCtx, safeLogW, tracker, frame.ID, fwdOpts, ael.ErrCapacity)
				break
			}
			// SendMessage returns context cancellation/deadline errors as-is
			// and sanitizes upstream request failures/status errors so raw
			// upstream bytes cannot cross this logging boundary.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			// A notification has no ID to answer, so a failure on one gets no
			// client reply; an error response with a null ID is a reply the
			// client never asked for. Notifications are never tracked, so an
			// intent receipt is closed from the input decision directly.
			if isRPCNotification(frame.ID) {
				if decision.Outcome.Receipt.ActionID != "" {
					emitMCPOutcomeReceipt(fwdOpts.receiptEmitter(), fwdOpts.v2ReceiptEmitter(), fwdOpts.ReceiptGroup, safeLogW, decision.Outcome.Receipt, "error", -1, "upstream_error", fwdOpts.requireReceipts())
				}
				continue
			}
			// Send sanitized error to client - don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := frame.ID
			errResp := upstreamErrorResponse(rpcID, fmt.Errorf("upstream HTTP request failed"))
			if wErr := safeClientOut.WriteMessage(errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send error response: %v\n", wErr)
			}
			emitTrackedTerminalOutcome(safeLogW, tracker, frame.ID, errResp, "upstream_error", fwdOpts)
			continue
		}

		// Scan and forward response. Apply the optional per-read response
		// timeout (no-op when disabled) so a hung HTTP upstream fails closed.
		foundInjection, scanErr := scanMCPHTTPResponse(requestCtx, respReader, safeClientOut, safeLogW, tracker, fwdOpts)
		if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(context.Cause(requestCtx), ael.ErrCapacity) {
			emitTrackedStreamError(requestCtx, safeLogW, tracker, frame.ID, fwdOpts, ael.ErrCapacity)
			lastScanErr = ael.ErrCapacity
			unlockInventory()
			break
		}
		if errors.Is(scanErr, transport.ErrResponseTimeout) {
			emitRequestScopedTimeout(
				respReader,
				safeClientOut,
				safeLogW,
				tracker,
				frame.ID,
				"pipelock: upstream response timeout; failed request closed, session continues",
				fwdOpts,
			)
			lastScanErr = scanErr
			unlockInventory()
			continue
		}
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			logMCPIncompleteResponse(safeLogW, fwdOpts, frame.Method, scanErr)
			if errors.Is(scanErr, transport.ErrIncompleteResponse) || ctx.Err() != nil {
				emitTrackedStreamError(ctx, safeLogW, tracker, frame.ID, fwdOpts, scanErr)
			} else {
				emitTrackedIncompleteOutcome(safeLogW, tracker, frame.ID, "scan_error", fwdOpts)
			}
			lastScanErr = scanErr
		} else if !foundInjection {
			commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), mcpFrameBaselineIdentity(frame))
		}

		unlockInventory()

		// After first successful response with a session ID, start GET stream
		// for server-initiated messages. Check session ID OUTSIDE the Once so
		// that early responses without a session ID (e.g. 202) don't consume
		// the Once and permanently prevent the GET stream.
		if httpClient.SessionID() != "" {
			getStreamOnce.Do(func() {
				startGETStream(ctx, httpClient, safeClientOut, safeLogW, fwdOpts, getResponseTracker, &wg)
			})
		}
	}

	// Stop the GET stream and any held-call release before terminating the
	// session. DeleteSession clears the negotiated version, so a release sent
	// after it would leave without its modern request metadata; releases send
	// on ctx, and DeleteSession uses its own context.
	cancel()
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession(safeLogW)
	}
	wg.Wait()
	emitPendingIncompleteOutcomes(safeLogW, tracker, fwdOpts, "upstream_closed")

	if err := opts.nativeCapacityStopError(); err != nil {
		return err
	}
	return lastScanErr
}

// mcpLocalRefusedOutcome closes tracking and preserves the admission identity.
// In best-effort mode, a locally refused call needs an intent before its
// blocked outcome can be recorded under that same identity.
func mcpLocalRefusedOutcome(tracker *RequestTracker, id json.RawMessage, decision httpInputDecision) TrackedRequestOutcome {
	outcome := decision.Outcome
	if !isRPCNotification(id) {
		if tracked, ok := consumeTrackedRequestOutcome(tracker, id); ok {
			outcome = tracked
		}
	}
	if pending := decision.pendingReceipt; pending != nil {
		outcome.releaseNativeLease()
		outcome.ownsNativeLease = false
		outcome.Receipt = pendingRefusalIntent(pending)
	}
	return outcome
}

// pendingRefusalIntent writes a held best-effort allow as an intent and
// returns the identity its blocked outcome must reuse.
func pendingRefusalIntent(pending *mcpToolReceiptOpts) receipt.EmitOpts {
	pending.DecisionPhase = receipt.DecisionPhaseIntent
	emitPendingMCPInputReceipt(pending)
	return pending.ProxyOpts.withReceiptPolicyHash(pending.receiptOptions())
}

func emitPendingMCPInputReceipt(pending *mcpToolReceiptOpts) {
	if pending != nil {
		_ = emitMCPToolReceipt(*pending)
	}
}

func emitBridgeHeaderContractRefusal(logW io.Writer, outcome TrackedRequestOutcome, reason string, opts MCPProxyOpts) {
	defer outcome.releaseNativeLease()
	intent := outcome.Receipt
	intent.Layer = mcpReceiptLayerHeaderContract
	emitMCPBlockedOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, intent, -1, reason, opts.requireReceipts())
}
