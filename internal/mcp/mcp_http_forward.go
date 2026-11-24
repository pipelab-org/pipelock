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
	"sync/atomic"
	"time"

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
		outcome, ok := consumeTrackedRequestOutcome(tracker, id, opts)
		if ok {
			emitMCPTimeoutReply(writer, logW, id, outcome, opts)
		}
	}
	_, _ = fmt.Fprintln(logW, logMessage)
}

// emitContractRefusedOutcome writes the blocked outcome for a call the live
// upstream contract refused. Notifications are never tracked, so their caller
// passes the outcome from the input decision directly.
func emitContractRefusedOutcome(logW io.Writer, outcome TrackedRequestOutcome, gate mcpContractGateOutput, reason string, bytesTransferred int64, opts MCPProxyOpts) {
	receiptOpts := mcpWithContractReceipt(outcome.Receipt, gate)
	receiptOpts.Layer = mcpContractReceiptLayer
	outcome.Receipt = receiptOpts
	outcome.settle(logW, opts, mcpOutcomeStatusBlocked, bytesTransferred, reason)
}

func emitTrackedIncompleteOutcome(logW io.Writer, tracker *RequestTracker, id json.RawMessage, reason string, opts MCPProxyOpts) {
	outcome, ok := consumeTrackedRequestOutcome(tracker, id, opts)
	if !ok {
		return
	}
	outcome.settle(logW, opts, "incomplete", -1, reason)
}

func settleBridgeCapacityOutcome(ctx context.Context, logW io.Writer, tracker *RequestTracker, id json.RawMessage, opts MCPProxyOpts, outcome TrackedRequestOutcome) {
	if isRPCNotification(id) && outcome.Receipt.ActionID != "" {
		outcome.settle(logW, opts, "cancelled", -1, nativeCapacityReason)
		return
	}
	emitTrackedStreamError(ctx, logW, tracker, id, opts, ael.ErrCapacity)
}

func settleBridgeNotificationScanError(ctx context.Context, logW io.Writer, opts MCPProxyOpts, outcome TrackedRequestOutcome, err error) {
	status, reason := "incomplete", "scan_error"
	if errors.Is(err, transport.ErrIncompleteResponse) || ctx.Err() != nil {
		reason = httpstream.Reason(ctx, err)
		if reason == httpstream.Cancelled {
			status = "cancelled"
		}
	}
	outcome.settle(logW, opts, status, -1, reason)
}

func consumeTrackedRequestOutcome(tracker *RequestTracker, id json.RawMessage, opts MCPProxyOpts) (TrackedRequestOutcome, bool) {
	if opts.v3POST != nil {
		return tracker.takeOwnedOutcome(id, opts.v3POST.registration)
	}
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

func (o MCPProxyOpts) finishV3HTTPAcknowledgement(ctx context.Context, logW io.Writer, effect *mcpV3Exchange, tracker *RequestTracker, id json.RawMessage, registration *requestRegistration) {
	logMCPV3Error(logW, confirmMCPV3Effect(ctx, effect.token, true))
	o.finishV3Send(ctx, logW, effect, true)
	if pending, ok := tracker.takeOwnedOutcome(id, registration); ok {
		pending.settle(logW, o, "forwarded", -1, "upstream_acknowledged")
	}
}

func interruptBridgeHeldOutput(out io.Writer, grace time.Duration) func() {
	deadline, ok := out.(interface{ SetWriteDeadline(time.Time) error })
	if !ok {
		return func() {}
	}
	done := make(chan struct{})
	timer := time.AfterFunc(grace, func() {
		defer close(done)
		_ = deadline.SetWriteDeadline(time.Now())
	})
	return func() {
		if !timer.Stop() {
			<-done
		}
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
	wireClientOut := newMCPClientWriter(clientOut, opts)
	safeLogW := &syncWriter{w: logW}
	ctx, cancel, sessionExit := newSessionBoundContext(ctx, startupParentWatch, clientIn, safeLogW, opts.sessionExitForTest)
	defer cancel()
	defer opts.closeNativeInputOnStop(clientIn)()
	ctx, cancelCapacity := context.WithCancelCause(ctx)
	defer cancelCapacity(nil)
	opts.onLocalV3ReplyFailure = func(err error) {
		cancelCapacity(err)
		if closer, ok := clientIn.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	defer opts.nativeCapacity().OnStopAfter(opts.shutdownGrace(), func() {
		cancelCapacity(ael.ErrCapacity)
		interruptNativeOutput(clientOut)
	})()

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
	opts = opts.withV3Session()
	opts.WarnContext = ctx
	safeClientOut := opts.localV3ReplyWriter(wireClientOut, safeLogW, nil)
	defer opts.settleV3Session(ctx, safeLogW)

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
	var heldWork sync.WaitGroup
	drainHeld := sync.OnceFunc(func() {
		if fwdOpts.receiptEffects.enabled {
			defer interruptBridgeHeldOutput(clientOut, fwdOpts.shutdownGrace())()
			cancel()
		}
		stopKillWatch()
		resolverRuntime.Cancel()
		if manager := fwdOpts.deferManager(); manager != nil {
			manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
		}
		resolverRuntime.Wait()
		<-capacityDeferralsDone
		if fwdOpts.receiptEffects.enabled {
			// A callback may still settle a receipt. For an output without
			// write deadlines, shutdown waits until its write returns.
			heldWork.Wait()
		}
	})
	defer drainHeld()

	bridgeHeaders := &mcpBridgeHeaders{client: httpClient, state: contractState, opts: fwdOpts, log: safeLogW}
	bridgeHeaders.opts.ToolCfg = fwdToolCfg

	clientReader := transport.NewStdioReader(clientIn)

	var wg sync.WaitGroup
	var getStreamOnce sync.Once
	var lastScanErr error
	var admission receipt.EmitOpts
	finishWarnings := func() {}
	settleAdmission := func() {
		finishWarnings()
		admission.ReleaseNativeAdmission()
	}
	defer settleAdmission()

	for {
		settleAdmission()
		finishWarnings = func() {}
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
			writeNativeAdmissionDenial(fwdOpts, safeLogW, safeClientOut, frame, admissionErr)
			lastScanErr = admissionErr
			break
		}
		fwdOpts.nativeAdmission = admission
		fwdOpts.WarnContext, finishWarnings = fwdOpts.nativeWarningContext(fwdOpts.warnContext(), admission)
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
					if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, batchResp); wErr != nil {
						_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send kill switch response: %v\n", wErr)
					}
					continue
				}
				if d.IsNotification {
					dropMCPInputNotification(fwdOpts, safeLogW, denialAudit, frame)
					_, _ = fmt.Fprintf(safeLogW, "pipelock: kill switch dropped notification (source=%s)\n", d.Source)
					continue
				}
				rpcID := frame.ID
				resp := killswitch.ErrorResponse(rpcID, d.Message)
				if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, resp); wErr != nil {
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
					_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, resp)
				}
				continue
			}
			deferredReq := decision.Deferred
			v3Hold := fwdOpts.receiptEffects.enabled
			var v3Release deferred.Release
			var v3HeldEvidence receipt.EmitOpts
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
			if holdErr == nil && (heldOpts.nativeAdmission.NativeLease != nil || v3Hold) {
				heldWork.Add(1)
				release := finishHeldAdmission
				finishHeldAdmission = func() {
					defer heldWork.Done()
					release()
				}
			}
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
					prepared := res
					var finish func()
					if v3Hold {
						// The HTTP client synchronizes its own session state.
						// No round trip may hold up a committed parent's children.
						var claimed bool
						finish, claimed = claimDeferredRelease(heldOpts, deferredGeneration)
						if !claimed {
							markDeferredKillSwitch(&prepared)
						}
					} else {
						prepared, finish = lockAndClaimDeferredRelease(&upstreamMu, heldOpts, deferredGeneration, res)
					}
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
					if !v3Hold {
						prepared = receiptSettle.probeAllow(heldOpts, prepared)
					}
					return prepared, finish
				},
				// The release receipt is written while the journal shows the
				// release as pending: the allow first, then a corrective block
				// if the journal cannot record the allow as final.
				AfterJournal: func(res deferred.Resolution) error {
					return receiptSettle.commitRelease(heldOpts, safeLogW, res)
				},
				ResolveWithReleaseRefusal: func(res deferred.Resolution, refuse func(string) deferred.Resolution) {
					defer finishHeldAdmission()
					denialOpts := heldOpts
					denialOpts.denialTerminal = &terminalSlot
					denialAudit := mcpDeferredDenialAudit(res)
					if gateBlock != nil {
						denialAudit = gateAudit
					}
					authorityDenied := res.ResolutionSource == deferred.SourceAuthority
					var emitErr error
					if !v3Hold {
						emitErr = receiptSettle.ensure(heldOpts, safeLogW, res)
					}
					if emitErr != nil {
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
							_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32007,
								ErrorMessage: "pipelock: receipt emission failed",
							}))
						}
						return
					}
					switch res.FinalDecision {
					case config.ActionAllow:
						releaseOutcome := receiptSettle.release
						releaseOutcome.Method = res.Method
						var readyToCorrelate atomic.Bool
						if v3Hold {
							releaseOutcome.readyToCorrelate = &readyToCorrelate
						}
						var registration *requestRegistration
						if isTrackableRequest(deferredReq.ForwardMessage, deferredReq.ID) {
							releaseOutcome.Receipt = releaseOutcome.Receipt.InheritAdmission(heldOpts.nativeAdmission)
							var trackErr error
							registration, trackErr = trackMCPAdmittedOutcome(safeLogW, heldOpts, tracker, deferredReq.ID, releaseOutcome)
							if trackErr == nil && v3Hold && registration == nil {
								trackErr = errors.New("could not reserve the held request ID")
							}
							if trackErr != nil {
								refuse("request_tracking_failed")
								if finishDeniedRelease != nil {
									finishDeniedRelease()
								}
								writeNativeAdmissionDenial(heldOpts, safeLogW, safeClientOut, deferredReq.authorityFrame, trackErr)
								return
							}
						}
						awaitingReply := false
						defer func() {
							if awaitingReply {
								return
							}
							if pending, ok := tracker.takeOwnedOutcome(deferredReq.ID, registration); ok {
								pending.settle(safeLogW, heldOpts, "incomplete", -1, "upstream_no_response")
							}
						}()
						if reason := mcpTaskReleaseRefusal(heldOpts, deferredReq.authorityFrame, deferredReq.taskTaint, false); reason != "" {
							if pending, ok := tracker.takeOwnedOutcome(deferredReq.ID, registration); ok {
								receiptSettle.release = pending
							}
							refuse(reason)
							if finishDeniedRelease != nil {
								finishDeniedRelease()
							}
							if deferredReq.IsNotification {
								dropMCPDenial(denialOpts, mcpTaintDenialAudit(), "input")
							} else {
								_ = writeMCPInputDenial(denialOpts, mcpTaintDenialAudit(), safeClientOut, deferredReq.authorityFrame, blockRequestResponse(BlockedRequest{
									ID: deferredReq.ID, ErrorCode: -32002, ErrorMessage: "pipelock: " + reason,
								}))
							}
							return
						}
						releaseCtx := heldOpts.warnContext()
						releaseOpts := heldOpts
						messageOpts := transport.HTTPMessageOptions{Headers: releaseHeaders}
						var exchange *mcpV3Exchange
						// localReply links a held call's local error reply to its
						// upstream send, as the non-held path does.
						localReply := safeClientOut
						var wrote func() bool
						var roundTripConfirmed bool
						if v3Hold {
							var admitErr error
							exchange, admitErr = heldOpts.admitV3HeldSend(releaseCtx, v3HeldEvidence, v3Release)
							releaseCtx, wrote = observeMCPHTTPWrite(releaseCtx)
							messageOpts.ObserveRoundTrip = func(err error) { roundTripConfirmed = err == nil }
							releaseErr := errors.Join(admitErr, releaseCtx.Err(), v3Release.ApprovalContext.Err())
							if releaseErr == nil {
								releaseErr = heldOpts.commitV3HeldSend(exchange, v3Release, &readyToCorrelate)
							}
							if releaseErr == nil {
								localReply = heldOpts.localV3ReplyWriter(wireClientOut, safeLogW, exchange)
							}
							if releaseErr != nil {
								tracker.removeOwnedOutcome(deferredReq.ID, registration)
								if admitErr == nil {
									heldOpts.refuseV3HeldIntent(releaseCtx, exchange, v3Release)
								}
								finishDeniedRelease()
								logMCPV3Error(safeLogW, admitErr)
								if deferredReq.IsNotification {
									dropMCPDenial(denialOpts, mcpReceiptMcpInputDenialAudit(), "input")
								} else {
									br := mcpV3HeldSendDenial(deferredReq.authorityFrame, v3HeldEvidence, exchange, releaseErr)
									inputMCPDenial(denialOpts, mcpReceiptMcpInputDenialAudit(), &br)
									_ = deliverMCPInputResult(denialOpts, br, heldOpts.v3SendDenialWriter(wireClientOut, safeLogW, br))
								}
								return
							}
						}
						respReader, sendErr := httpClient.SendMessageWithOptions(releaseCtx, deferredReq.ForwardMessage, messageOpts)
						if v3Hold {
							heldOpts.confirmV3HeldSend(releaseCtx, safeLogW, exchange, roundTripConfirmed && wrote())
							releaseOpts = releaseOpts.withV3POST(exchange, registration)
							if sendErr != nil || deferredReq.IsNotification {
								heldOpts.unbindV3Send(exchange)
							} else {
								defer func() {
									if !awaitingReply {
										heldOpts.unbindV3Send(exchange)
									}
								}()
							}
						}
						if sendErr != nil {
							if errors.Is(context.Cause(releaseCtx), ael.ErrCapacity) {
								settleBridgeCapacityOutcome(releaseCtx, safeLogW, tracker, deferredReq.ID, releaseOpts, releaseOutcome)
								return
							}
							if pending, ok := tracker.takeOwnedOutcome(deferredReq.ID, registration); ok {
								releaseOutcome = pending
							}
							releaseOutcome.settle(safeLogW, heldOpts, "error", -1, mcpUpstreamWriteFailed)
							if !v3Hold {
								refuse(mcpUpstreamWriteFailed)
							}
							if finishDeniedRelease != nil {
								finishDeniedRelease()
							}
							if !deferredReq.IsNotification {
								_ = localReply.WriteMessage(upstreamErrorResponse(deferredReq.ID, fmt.Errorf("upstream HTTP request failed")))
							}
							return
						}
						if transport.IsStreamingResponse(respReader) {
							releaseOpts.nativeSSE = true
						}
						acknowledged := transport.IsHTTPAcknowledgement(respReader)
						if v3Hold && acknowledged && registration != nil {
							heldOpts.finishV3HTTPAcknowledgement(releaseCtx, safeLogW, exchange, tracker, deferredReq.ID, registration)
						}
						respReader = releaseOpts.withResponseTimeout(respReader)
						// ForwardScanned selects the v3 reply writer after correlating
						// the response. Give it the raw serialized sink so exactly one
						// exchange admits and settles delivery.
						responseOutput := safeClientOut
						if v3Hold {
							responseOutput = wireClientOut
						}
						foundInjection, scanErr := ForwardScanned(respReader, responseOutput, safeLogW, tracker, releaseOpts)
						if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(context.Cause(releaseCtx), ael.ErrCapacity) {
							settleBridgeCapacityOutcome(releaseCtx, safeLogW, tracker, deferredReq.ID, releaseOpts, releaseOutcome)
						} else if errors.Is(scanErr, transport.ErrResponseTimeout) {
							if deferredReq.IsNotification {
								releaseOutcome.settle(safeLogW, releaseOpts, "error", -1, "response_timeout")
							}
							emitRequestScopedTimeout(
								respReader,
								localReply,
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
							if deferredReq.IsNotification {
								settleBridgeNotificationScanError(releaseCtx, safeLogW, releaseOpts, releaseOutcome, scanErr)
							} else if outcome, pending := tracker.takeOwnedOutcome(deferredReq.ID, registration); pending {
								errResp := upstreamErrorResponse(deferredReq.ID, fmt.Errorf("upstream HTTP response failed"))
								_ = localReply.WriteMessage(errResp)
								status, reason, size := "error", "scan_error", int64(len(errResp))
								streamReason := httpstream.Reason(releaseCtx, scanErr)
								switch {
								case streamReason == httpstream.Cancelled:
									status, reason, size = "cancelled", streamReason, -1
								case errors.Is(scanErr, transport.ErrIncompleteResponse):
									status, reason, size = "incomplete", streamReason, -1
								}
								outcome.settle(safeLogW, releaseOpts, status, size, reason)
							}
						} else {
							if deferredReq.IsNotification {
								releaseOutcome.settle(safeLogW, releaseOpts, "forwarded", -1, "notification_forwarded")
							}
							if !foundInjection {
								awaitingReply = !v3Hold && registration != nil && acknowledged
								baselineIdentity := deferredReq.BaselineIdentity
								if baselineIdentity == "" {
									baselineIdentity = mcpFrameBaselineIdentity(ParseMCPFrame(deferredReq.ForwardMessage))
								}
								commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), baselineIdentity)
							}
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
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, blockRequestResponse(*authorityBlockedRequest(deferredReq.authorityFrame)))
								return
							}
							if gateBlock != nil {
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, blockRequestResponse(*gateBlock))
								return
							}
							if res.ResolutionSource == deferred.SourceKillSwitch {
								_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, killswitch.ErrorResponse(deferredReq.ID, deferredKillSwitchMessage(fwdOpts)))
								return
							}
							_ = writeMCPInputDenial(denialOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, blockRequestResponse(BlockedRequest{
								ID:           deferredReq.ID,
								ErrorCode:    -32002,
								ErrorMessage: "pipelock: deferred action denied",
							}))
						}
					}
				},
			}
			if v3Hold {
				v3HeldEvidence = heldOpts.setupV3Hold(&heldAction, decision.v3Evidence)
				resolve := heldAction.ResolveWithReleaseRefusal
				heldAction.ResolveWithReleaseRefusal = nil
				heldAction.ResolveReceipt = func(res deferred.Resolution, release deferred.Release) {
					v3Release = release
					resolve(res, func(reason string) deferred.Resolution { return release.Refuse(reason, nil) })
				}
			}
			if holdErr == nil {
				holdErr = manager.HoldContext(heldOpts.warnContext(), heldAction)
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
					_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, deferredReq.authorityFrame, blockRequestResponse(BlockedRequest{
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

		if gate, gateErr := evaluateMCPUpstreamGate(ctx, upstreamURL, opts); gateErr != nil {
			outcome := decision.Outcome
			denialAudit = mcpListenerContractEvalDenialAudit()
			_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream evaluation failed: %v\n", gateErr)
			// Notifications have no id; JSON-RPC forbids responses to
			// them. Mirror the kill-switch and input-scan paths above.
			if isRPCNotification(frame.ID) {
				dropMCPInputNotification(fwdOpts, safeLogW, denialAudit, frame)
				emitContractRefusedOutcome(safeLogW, outcome, mcpContractGateOutput{}, mcpContractEvaluationFailedReason, 0, fwdOpts)
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, mcpContractGateOutput{}, "pipelock: contract upstream evaluation failed"))
			if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitContractRefusedOutcome(safeLogW, outcome, mcpContractGateOutput{}, mcpContractEvaluationFailedReason, int64(len(errResp)), fwdOpts)
			continue
		} else if gate.Verdict == config.ActionBlock {
			outcome := decision.Outcome
			denialAudit = mcpUpstreamGateDenialAudit(gate)
			if gate.WinningSource == contractruntime.WinningSourceScanner {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream scanner denied: %s\n", gate.Reason)
			} else {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: contract upstream denied: %s\n", gate.Reason)
			}
			if isRPCNotification(frame.ID) {
				dropMCPInputNotification(fwdOpts, safeLogW, denialAudit, frame)
				emitContractRefusedOutcome(safeLogW, outcome, gate, mcpContractDeniedReason, 0, fwdOpts)
				continue
			}
			errResp := blockRequestResponse(mcpContractBlockRequest(frame.ID, gate, "pipelock: upstream URL blocked by live-lock contract"))
			if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, errResp); wErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send contract response: %v\n", wErr)
			}
			emitContractRefusedOutcome(safeLogW, outcome, gate, mcpContractDeniedReason, int64(len(errResp)), fwdOpts)
			continue
		}

		requestHeaders, headerErr := bridgeHeaders.prepare(ctx, decision.ForwardMessage)
		if headerErr != nil {
			outcome := decision.Outcome
			_, _ = fmt.Fprintf(safeLogW, "pipelock: header contract refused: %q\n", headerErr.Error())
			denialAudit, message, reason := bridgeHeaderRefusal(headerErr)
			// Notifications are never tracked: close their intent from the input
			// decision, as the upstream gate above does.
			if isRPCNotification(frame.ID) {
				dropMCPInputNotification(fwdOpts, safeLogW, denialAudit, frame)
				emitBridgeHeaderContractRefusal(safeLogW, outcome, reason, fwdOpts)
				continue
			}
			response := blockRequestResponse(BlockedRequest{ID: frame.ID, ErrorCode: -32020, ErrorMessage: message})
			_ = writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, response)
			emitBridgeHeaderContractRefusal(safeLogW, outcome, reason, fwdOpts)
			continue
		}

		effect, admitErr := fwdOpts.startV3Send(ctx, frame, decision.v3Evidence)
		if admitErr != nil {
			decision.Outcome.settle(safeLogW, fwdOpts, "blocked", -1, "receipt_admission_failed")
			logMCPV3Error(safeLogW, admitErr)
			_ = fwdOpts.writeV3SendDenial(safeLogW, wireClientOut, frame, effect, admitErr)
			continue
		}
		unlockInventory := func() {}
		if frame.Method == "tools/list" {
			if lockErr := contractState.contractMu.Lock(ctx); lockErr != nil {
				fwdOpts.finishV3Send(ctx, safeLogW, effect, false)
				// Only cancellation fails this wait. Close the request's
				// tracked outcome and leave through the shared shutdown path,
				// which settles other pending outcomes and ends the session.
				_, _ = fmt.Fprintf(safeLogW, "pipelock: inventory lock not acquired: %v\n", lockErr)
				decision.Outcome.settle(safeLogW, fwdOpts, "incomplete", -1, "inventory_wait_ended")
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
		attempted := false
		var registration *requestRegistration
		// POST to upstream.
		awaitReply := isTrackableRequest(decision.ForwardMessage, frame.ID)
		sendCtx := ctx
		messageOpts := transport.HTTPMessageOptions{Headers: requestHeaders}
		var roundTripConfirmed bool
		var wroteOneWay func() bool
		if effect != nil && !awaitReply {
			sendCtx, wroteOneWay = observeMCPHTTPWrite(ctx)
			messageOpts.ObserveRoundTrip = func(err error) { roundTripConfirmed = err == nil }
		}
		var taskRefusal string
		var trackingErr error
		respReader, err := func() (transport.MessageReader, error) {
			upstreamMu.Lock()
			defer upstreamMu.Unlock()
			if effect != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			taskRefusal = mcpTaskReleaseRefusal(fwdOpts, decision.taskFrame, decision.taskTaint, false)
			if taskRefusal != "" {
				return nil, nil
			}
			if awaitReply {
				decision.Outcome.Method = frame.Method
				decision.Outcome.Receipt = decision.Outcome.Receipt.InheritAdmission(admission)
				registration, trackingErr = trackMCPAdmittedOutcome(safeLogW, fwdOpts, tracker, frame.ID, decision.Outcome)
				if trackingErr != nil {
					return nil, nil
				}
				taskRefusal = mcpTaskReleaseRefusal(fwdOpts, decision.taskFrame, decision.taskTaint, false)
				if taskRefusal != "" {
					tracker.removeOwnedOutcome(frame.ID, registration)
					return nil, nil
				}
				if bindErr := fwdOpts.bindV3Send(effect); bindErr != nil {
					tracker.removeOwnedOutcome(frame.ID, registration)
					trackingErr = bindErr
					return nil, nil
				}
			}
			attempted = true
			return httpClient.SendMessageWithOptions(sendCtx, decision.ForwardMessage, messageOpts)
		}()
		switch {
		case !attempted:
			fwdOpts.finishV3Send(ctx, safeLogW, effect, false)
		case wroteOneWay != nil:
			logMCPV3Error(safeLogW, confirmMCPV3Effect(ctx, effect.token, roundTripConfirmed && wroteOneWay()))
		case err != nil:
			fwdOpts.finishV3Send(ctx, safeLogW, effect, true)
		}
		if trackingErr != nil {
			unlockInventory()
			decision.Outcome.settle(safeLogW, fwdOpts, mcpOutcomeStatusBlocked, -1, "request_tracking_failed")
			writeNativeAdmissionDenial(fwdOpts, safeLogW, safeClientOut, frame, trackingErr)
			continue
		}
		if taskRefusal != "" {
			unlockInventory()
			denialAudit := mcpTaintDenialAudit()
			outcome := decision.Outcome
			var errResp []byte
			if isRPCNotification(frame.ID) {
				dropMCPInputNotification(fwdOpts, safeLogW, denialAudit, frame)
			} else {
				block := BlockedRequest{ID: frame.ID, ErrorCode: -32002, ErrorMessage: "pipelock: " + taskRefusal}
				errResp = blockRequestResponse(block)
				if wErr := writeMCPInputDenial(fwdOpts, denialAudit, safeClientOut, frame, errResp); wErr != nil {
					_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send task refusal: %v\n", wErr)
				}
			}
			reason := decision.taskTaint.recordTaskReleaseRefusal(taskRefusal)
			outcome.Receipt.Layer = mcpReceiptLayerTaint
			outcome.Receipt.TaintDecision = config.ActionBlock
			outcome.Receipt.TaintDecisionReason = reason
			outcome.settle(safeLogW, fwdOpts, mcpOutcomeStatusBlocked, int64(len(errResp)), reason)
			continue
		}
		if err != nil {
			unlockInventory()
			if errors.Is(context.Cause(ctx), ael.ErrCapacity) {
				settleBridgeCapacityOutcome(ctx, safeLogW, tracker, frame.ID, fwdOpts, decision.Outcome)
				break
			}
			// SendMessage returns context cancellation/deadline errors as-is
			// and sanitizes upstream request failures/status errors so raw
			// upstream bytes cannot cross this logging boundary.
			_, _ = fmt.Fprintf(safeLogW, "pipelock: upstream error: %v\n", err)
			warnTransportAdmission(safeLogW, fwdOpts, decision.admission, "upstream_error")
			// One-way messages are never tracked and receive no JSON-RPC reply.
			// Close any legacy intent from the input decision directly.
			if !awaitReply {
				if decision.Outcome.Receipt.ActionID != "" {
					decision.Outcome.settle(safeLogW, fwdOpts, "error", -1, "upstream_error")
				}
				continue
			}
			// Send sanitized error to client - don't include upstream body content
			// which could contain prompt injection payloads.
			rpcID := frame.ID
			errResp := upstreamErrorResponse(rpcID, fmt.Errorf("upstream HTTP request failed"))
			size := int64(len(errResp))
			var writeErr error
			if fwdOpts.receiptEffects.enabled {
				reply := fwdOpts.localV3ReplyWriter(wireClientOut, safeLogW, effect)
				writeErr = writeMCPDenial(fwdOpts, mcpResponseInspectionBlockAudit("upstream_error"), reply, errResp)
				if writeErr != nil {
					size = -1
				}
			} else {
				writeErr = wireClientOut.WriteMessage(errResp)
			}
			if writeErr != nil {
				_, _ = fmt.Fprintf(safeLogW, "pipelock: failed to send error response: %v\n", writeErr)
			}
			outcome := decision.Outcome
			if pending, ok := tracker.takeOwnedOutcome(frame.ID, registration); ok {
				outcome = pending
			}
			outcome.settle(safeLogW, fwdOpts, "error", size, "upstream_error")
			continue
		}

		// Scan and forward response. Apply the optional per-read response
		// timeout (no-op when disabled) so a hung HTTP upstream fails closed.
		acknowledged := transport.IsHTTPAcknowledgement(respReader)
		if acknowledged && effect != nil && awaitReply {
			fwdOpts.finishV3HTTPAcknowledgement(ctx, safeLogW, effect, tracker, frame.ID, registration)
		}
		if transport.IsStreamingResponse(respReader) {
			fwdOpts.nativeSSE = true
			fwdOpts.WarnContext = ctx
		}
		fwdOpts = fwdOpts.withV3POST(effect, registration)
		foundInjection, scanErr := ForwardScanned(fwdOpts.withResponseTimeout(respReader), wireClientOut, safeLogW, tracker, fwdOpts)
		if awaitReply && !acknowledged {
			fwdOpts.finishV3Send(ctx, safeLogW, effect, true)
		}
		if errors.Is(scanErr, ael.ErrCapacity) || errors.Is(context.Cause(ctx), ael.ErrCapacity) {
			settleBridgeCapacityOutcome(ctx, safeLogW, tracker, frame.ID, fwdOpts, decision.Outcome)
			lastScanErr = ael.ErrCapacity
			unlockInventory()
			break
		}
		if errors.Is(scanErr, transport.ErrResponseTimeout) {
			unlockInventory()
			emitRequestScopedTimeout(
				respReader,
				fwdOpts.localV3ReplyWriter(wireClientOut, safeLogW, effect),
				safeLogW,
				tracker,
				frame.ID,
				"pipelock: upstream response timeout; failed request closed, session continues",
				fwdOpts,
			)
			if isRPCNotification(frame.ID) {
				decision.Outcome.settle(safeLogW, fwdOpts, "error", -1, "response_timeout")
			}
			lastScanErr = scanErr
			continue
		}
		if scanErr != nil {
			_, _ = fmt.Fprintf(safeLogW, "pipelock: scan error: %v\n", scanErr)
			logMCPIncompleteResponse(safeLogW, fwdOpts, frame.Method, scanErr)
			if isRPCNotification(frame.ID) {
				settleBridgeNotificationScanError(ctx, safeLogW, fwdOpts, decision.Outcome, scanErr)
			} else if errors.Is(scanErr, transport.ErrIncompleteResponse) || ctx.Err() != nil {
				emitTrackedStreamError(ctx, safeLogW, tracker, frame.ID, fwdOpts, scanErr)
			} else {
				emitTrackedIncompleteOutcome(safeLogW, tracker, frame.ID, "scan_error", fwdOpts)
			}
			lastScanErr = scanErr
		} else if !foundInjection {
			commitMCPToolCall(baselineMetricsRecorder(fwdOpts, rec), mcpFrameBaselineIdentity(frame))
		}

		if isRPCNotification(frame.ID) {
			if scanErr == nil {
				decision.Outcome.settle(safeLogW, fwdOpts, "forwarded", -1, "notification_forwarded")
			}
		} else if !acknowledged {
			if pending, ok := tracker.takeOwnedOutcome(frame.ID, registration); ok {
				pending.settle(safeLogW, fwdOpts, "incomplete", -1, "upstream_no_response")
			}
		}

		unlockInventory()

		// After first successful response with a session ID, start GET stream
		// for server-initiated messages. Check session ID OUTSIDE the Once so
		// that early responses without a session ID (e.g. 202) don't consume
		// the Once and permanently prevent the GET stream.
		if httpClient.SessionID() != "" {
			getStreamOnce.Do(func() {
				getOpts := fwdOpts
				getOpts.v3Session, getOpts.v3POST = nil, nil
				startGETStream(ctx, httpClient, wireClientOut, safeLogW, getOpts, getResponseTracker, &wg)
			})
		}
	}

	// Capacity stops intake immediately. Let admitted background work settle
	// before deleting the upstream session, with I/O interrupted at the cutoff.
	if opts.nativeCapacityStopError() != nil && !opts.receiptEffects.enabled {
		heldWork.Wait()
		wg.Wait()
	}
	cancel()
	if opts.receiptEffects.enabled {
		drainHeld()
	}
	if httpClient.SessionID() != "" {
		httpClient.DeleteSession(safeLogW)
	}
	wg.Wait()
	emitPendingIncompleteOutcomes(safeLogW, tracker, fwdOpts, "upstream_closed")

	if err := opts.nativeCapacityStopError(); err != nil {
		return err
	}
	if err := context.Cause(ctx); errors.Is(err, errMCPV3ReplyAdmission) {
		return err
	}
	return lastScanErr
}

func emitBridgeHeaderContractRefusal(logW io.Writer, outcome TrackedRequestOutcome, reason string, opts MCPProxyOpts) {
	intent := outcome.Receipt
	intent.Layer = mcpReceiptLayerHeaderContract
	outcome.Receipt = intent
	outcome.settle(logW, opts, mcpOutcomeStatusBlocked, -1, reason)
}
