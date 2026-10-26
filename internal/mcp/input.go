// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/addressprotect"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/authority"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	decide "github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/mcp/jsonrpc"
	"github.com/luckyPipewrench/pipelock/internal/mcp/policy"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/normalize"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	adaptiveRecoveryTimer = "time_based_recovery"
	adaptiveRecoveryClean = "clean_request_recovery"
	adaptiveBlockedReason = "pipelock: blocked by adaptive enforcement"
)

type adaptiveRecoveryContext struct {
	sessionKey string
	scope      string
	reason     string
	clientIP   string
	requestID  string
	logger     *audit.Logger
	metrics    *metrics.Metrics
}

func adaptiveRecoveryContextWithWarnContext(ctx adaptiveRecoveryContext, warnCtx context.Context) adaptiveRecoveryContext {
	wc := scanner.DLPWarnContextFromCtx(warnCtx)
	ctx.clientIP = firstNonEmpty(ctx.clientIP, wc.ClientIP)
	ctx.requestID = firstNonEmpty(ctx.requestID, wc.RequestID)
	return ctx
}

// tryRecoverSession attempts autonomous de-escalation on the session recorder.
// No-op if rec does not implement session.Recoverer or adaptive enforcement is disabled.
func tryRecoverSession(rec session.Recorder, adaptiveCfg *config.AdaptiveEnforcement, ctx adaptiveRecoveryContext) {
	if adaptiveCfg == nil || !adaptiveCfg.Enabled {
		return
	}
	r, ok := rec.(session.Recoverer)
	if !ok {
		return
	}
	blockAllCheck := func(level int) bool {
		return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
	}
	levelDuration := time.Duration(adaptiveCfg.LevelDurationSeconds) * time.Second
	if levelDuration <= 0 {
		levelDuration = 5 * time.Minute
	}
	if changed, from, to := r.TryAutoRecover(levelDuration, blockAllCheck); changed {
		ctx.reason = firstNonEmpty(ctx.reason, adaptiveRecoveryTimer)
		emitAdaptiveRecovery(rec, from, to, ctx)
	}
}

func recordCleanSession(rec session.Recorder, adaptiveCfg *config.AdaptiveEnforcement, eligibleForCleanRecovery bool, ctx adaptiveRecoveryContext) {
	if rec == nil || adaptiveCfg == nil || !adaptiveCfg.Enabled {
		return
	}
	if !eligibleForCleanRecovery {
		rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
		return
	}
	if r, ok := rec.(session.CleanRecoverer); ok {
		blockAllCheck := func(level int) bool {
			return decide.UpgradeAction("", level, adaptiveCfg) == config.ActionBlock
		}
		changed, from, to := r.RecordCleanWithRecovery(adaptiveCfg.DecayPerCleanRequest, adaptiveCfg.CleanRequestsToDeescalate, blockAllCheck)
		if changed {
			ctx.reason = firstNonEmpty(ctx.reason, adaptiveRecoveryClean)
			emitAdaptiveRecovery(rec, from, to, ctx)
		}
		return
	}
	rec.RecordClean(adaptiveCfg.DecayPerCleanRequest)
}

func emitAdaptiveRecovery(rec session.Recorder, from, to int, ctx adaptiveRecoveryContext) {
	fromLabel := session.EscalationLabel(from)
	toLabel := session.EscalationLabel(to)
	if ctx.metrics != nil {
		ctx.metrics.RecordSessionAutoDeescalation(fromLabel, toLabel)
		if from > 0 {
			ctx.metrics.SetAdaptiveSessionLevel(fromLabel, -1)
		}
		if to > 0 {
			ctx.metrics.SetAdaptiveSessionLevel(toLabel, 1)
		}
	}
	if ctx.logger != nil {
		ctx.logger.LogAdaptiveRecovery(audit.LogAdaptiveRecoveryOptions{
			SessionKey: ctx.sessionKey,
			Scope:      ctx.scope,
			From:       fromLabel,
			To:         toLabel,
			Reason:     ctx.reason,
			ClientIP:   ctx.clientIP,
			RequestID:  ctx.requestID,
		})
	}
	if eventRec, ok := rec.(session.RecoveryEventRecorder); ok {
		eventRec.RecordAdaptiveRecoveryEvent(ctx.scope, ctx.reason, from, to)
	}
}

// methodToolsCall is the JSON-RPC method for MCP tool invocations.
const methodToolsCall = "tools/call"

// methodResourcesRead is the JSON-RPC method for MCP resource reads.
const methodResourcesRead = "resources/read"

const methodNotificationsInitialized = "notifications/initialized"

// isRequiredReceiptMetadataMethod reports whether method is part of the
// ordinary MCP handshake that must receive an action identity when
// require_receipts is enabled. tools/list has an established ActionRead
// classification; initialize and notifications/initialized remain
// ActionUnclassified under the existing receipt schema. None is a tool
// invocation or envelope-bearing operation.
func isRequiredReceiptMetadataMethod(method string) bool {
	return method == "initialize" || method == "tools/list" || method == methodNotificationsInitialized
}

func isRequiredReceiptHandshakeNotification(method string, id json.RawMessage) bool {
	return method == methodNotificationsInitialized && isRPCNotification(id)
}

// errPolicyBlocked is the error message returned when a tool call is denied by policy.
const errPolicyBlocked = "pipelock: request blocked by tool call policy"

// patternUnknown is the fallback DLP pattern name when Matches is empty but Clean is false.
const patternUnknown = "unknown"

// ceeStdioKey is the fixed CEE session key for stdio MCP proxies. A single
// subprocess means one session per process, so a static key is correct.
const ceeStdioKey = "_default|stdio"

// InputVerdict describes the outcome of scanning a single MCP request.
type InputVerdict struct {
	ID              json.RawMessage          `json:"id"`
	Method          string                   `json:"method,omitempty"`
	Clean           bool                     `json:"clean"`
	Action          string                   `json:"action,omitempty"`
	Matches         []scanner.TextDLPMatch   `json:"dlp_matches,omitempty"`
	Inject          []scanner.ResponseMatch  `json:"injection_matches,omitempty"`
	URLFindings     []scanner.Result         `json:"url_findings,omitempty"`
	AddressFindings []addressprotect.Finding `json:"address_findings,omitempty"`
	Error           string                   `json:"error,omitempty"`
	// RedactedDLPOnly is true when the pre-redaction scan matched DLP
	// patterns that argument redaction then scrubbed, and the post-redaction
	// rescan was clean. The request forwards scrubbed, but the pre-redaction
	// findings are retained here as the configured (warn) action so the match
	// is still recorded rather than silently dropped. Mirrors the request-body
	// floor's BodyScanResult.RedactedDLPOnly in internal/proxy/bodyscan.go.
	RedactedDLPOnly bool `json:"redacted_dlp_only,omitempty"`
}

// IsInformationalCardRuns excludes other findings and incomplete inspection.
func (v InputVerdict) IsInformationalCardRuns() bool {
	return scanner.OnlyInformational(v.Matches) && len(v.Inject) == 0 && len(v.URLFindings) == 0 && len(v.AddressFindings) == 0 && v.Error == "" && !v.RedactedDLPOnly
}

// IsEntropyOnly checks the findings rather than the transport's generic label.
func (v InputVerdict) IsEntropyOnly() bool {
	if len(v.URLFindings) == 0 || len(v.Matches) > 0 || len(v.Inject) > 0 ||
		len(v.AddressFindings) > 0 || v.Error != "" || v.RedactedDLPOnly {
		return false
	}
	for _, finding := range v.URLFindings {
		if !finding.IsEntropyOnly() {
			return false
		}
	}
	return true
}

// BlockedRequest holds the ID and notification status of a blocked MCP request,
// sent from the input scanning goroutine to the main goroutine via channel.
// When SyntheticResponse is non-nil, the consumer sends it as-is instead of
// generating an error response (used for redirect success results).
type BlockedRequest struct {
	terminal          *mcpTerminalDecision
	ID                json.RawMessage
	IsNotification    bool // Notifications have no ID - don't send error response.
	LogMessage        string
	ErrorCode         int    // 0 = use default -32001; -32002 = policy block
	ErrorMessage      string // empty = use default message
	ErrorData         json.RawMessage
	SyntheticResponse []byte // if set, send this instead of an error response
}

// blockRequestResponse generates a JSON-RPC 2.0 error response for a blocked request.
// Uses ErrorCode/ErrorMessage from BlockedRequest if set, otherwise defaults.
func blockRequestResponse(br BlockedRequest) []byte {
	code := br.ErrorCode
	if code == 0 {
		code = -32001
	}
	msg := br.ErrorMessage
	if msg == "" {
		msg = "pipelock: request blocked by MCP input scanning"
	}
	resp := rpcError{
		JSONRPC: jsonrpc.Version,
		ID:      br.ID,
		Error: rpcErrorDetail{
			Code:    code,
			Message: msg,
			Data:    br.ErrorData,
		},
	}
	data, _ := json.Marshal(resp) //nolint:errcheck // marshaling known-good struct
	return data
}

// SessionBindingConfig controls MCP session binding (tool inventory validation).
// When non-nil with a valid Baseline, tools/call requests are checked against
// the tool inventory captured from the first tools/list response.
type SessionBindingConfig struct {
	Baseline          *tools.ToolBaseline
	UnknownToolAction string // warn, block
	NoBaselineAction  string // warn, block (action when no baseline yet)
}

// ForwardScannedInput reads JSON-RPC 2.0 requests from reader, scans each for
// DLP and injection patterns, and forwards clean requests to writer.
// When policyCfg is non-nil, tool call policy rules are also checked
// independently of content scanning - the strictest action wins.
// When bindingCfg is non-nil, tools/call requests are validated against the
// session tool baseline.
// When tracker is non-nil, each forwarded request's ID is recorded so the
// response-side (ForwardScanned) can validate that response IDs were solicited.
// When cee is non-nil, outbound payloads are recorded for cross-request
// exfiltration detection (entropy budget and fragment reassembly DLP).
// When rec is non-nil and adaptiveCfg is enabled, threat signals are recorded
// and the effective action may be upgraded based on session escalation level.
// Blocked request IDs are sent via blockedCh so the main goroutine (which owns
// clientOut writes) can send error responses without concurrent write races.
func ForwardScannedInput(
	reader transport.MessageReader,
	writer transport.MessageWriter,
	logW io.Writer,
	action string,
	onParseError string,
	blockedCh chan<- BlockedRequest,
	bindingCfg *SessionBindingConfig,
	tracker *RequestTracker,
	opts MCPProxyOpts,
) {
	opts = opts.snapshotScanPolicy()
	sc := opts.scanner()
	policyCfg := opts.policyCfg()
	ks := opts.KillSwitch
	auditLogger := opts.AuditLogger
	cee := opts.cee()
	rec := opts.Rec
	adaptiveCfg := opts.adaptiveCfg()
	m := opts.Metrics
	obs := opts.captureObserver()
	redactionCfg := opts.redactionConfig()
	receiptEmitter := opts.receiptEmitter()
	policyHash := opts.receiptPolicyHash()
	envelopeEmitter := opts.envelopeEmitter()
	redirectRT := opts.redirectRT()
	resolverRuntime := opts.deferResolverRuntime()
	if resolverRuntime == nil {
		resolverRuntime = newDeferResolverRuntime(opts.warnContext())
	}

	// Held calls must not outlive a kill that arrives between messages (the
	// sentinel file has no event, and an API or signal activation only wakes
	// the next message). Stop the watcher before the final cancel below.
	killWatchCtx, stopKillWatch := context.WithCancel(context.Background())
	go watchDeferredKillSwitch(killWatchCtx, ks, opts.deferManager())
	defer func() {
		stopKillWatch()
		resolverRuntime.Cancel()
		if manager := opts.deferManager(); manager != nil {
			manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
		}
		resolverRuntime.Wait()
		close(blockedCh)
	}()
	var forwardMu sync.Mutex
	forwardMessage := func(msg []byte) error {
		forwardMu.Lock()
		defer forwardMu.Unlock()
		return writer.WriteMessage(msg)
	}

	// Helper: record an adaptive signal and handle escalation side-effects.
	// Eliminates repeated nil/enabled guards at every call site.
	hadAdaptiveFinding := false
	recordAdaptiveFinding := func(sig session.SignalType, scannerName, reason string) {
		hadAdaptiveFinding = true
		if adaptiveCfg != nil && adaptiveCfg.Enabled {
			recordMCPAdaptiveSignal(opts, rec, sig, decide.EscalationParams{
				Threshold:     adaptiveCfg.EscalationThreshold,
				Logger:        auditLogger,
				Metrics:       m,
				ConsoleWriter: logW,
				Session:       "default",
				DenialScanner: scannerName,
				DenialReason:  reason,
				PolicyHash:    policyHash,
			})
		}
	}
	recordAdaptiveSignal := func(sig session.SignalType) {
		recordAdaptiveFinding(sig, "", "")
	}

	// lineNum counts non-empty messages, not raw lines. StdioReader skips
	// empty lines internally, so this is a message index.
	lineNum := 0

	for {
		line, err := reader.ReadMessage()
		if err != nil {
			expectedClose := opts.sessionExit.inProgress() && isSessionExitCloseErr(err)
			if !errors.Is(err, io.EOF) && !expectedClose {
				_, _ = fmt.Fprintf(logW, "pipelock: input scanner error: %v\n", err)
			}
			return
		}
		lineNum++
		var denialAudit mcpDenialAudit
		hadAdaptiveFinding = false
		var deferredGeneration uint64
		if ks != nil {
			deferredGeneration = ks.DeferredGeneration()
		}

		// Consume both Pipelock-owned _meta members before scanning:
		// com.pipelock/mediation cannot be spoofed through to the server,
		// while com.pipelock/authority is removed and validated. The carrier
		// error is load-bearing: authorizeMCP fails this message closed when a
		// verifier is configured and the authority reference is unsafe.
		line, authorityRef, authorityCarrierErr := extractInboundMCPAuthority(line)

		// Parse the inbound frame once per message. Every gate below
		// reads ID / Method / tool fields from this frame instead of
		// re-parsing the bytes. Redaction may rewrite the argument
		// values later in the loop; the frame is re-parsed after the
		// redaction step so downstream gates (DoW, taint) see the
		// redacted args while ID / Method / ToolCallName stay stable.
		frame := ParseMCPFrame(line)

		// Kill switch: deny all messages when active.
		if ks != nil {
			if d := ks.IsActiveMCP(line); d.Active {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditKillSwitch, mcpKillSwitchReason, audit.BlockClassProtective)
				if manager := opts.deferManager(); manager != nil {
					manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
				}
				batchResp := refuseKillSwitchRequest(opts, logW, frame, d)
				if batchResp != nil {
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						LogMessage:        fmt.Sprintf("pipelock: input line %d: kill switch denied batch (source=%s)", lineNum, d.Source),
						SyntheticResponse: batchResp,
					}, blockedCh)
					continue
				}
				if d.IsNotification {
					dropMCPDenial(opts, denialAudit, "input")
					// Notifications have no ID - silently drop.
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: kill switch dropped notification (source=%s)\n",
						lineNum, d.Source)
				} else {
					// Request with ID - send JSON-RPC error response.
					rpcID := frame.ID
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             rpcID,
						IsNotification: false,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: kill switch denied (source=%s)", lineNum, d.Source),
						ErrorCode:      -32004,
						ErrorMessage:   d.Message,
					}, blockedCh)
				}
				continue
			}
		}

		// On-entry de-escalation: recover sessions stuck at block_all.
		// Runs before any per-message action so both clean and non-clean
		// messages benefit from recovery.
		if rec != nil {
			tryRecoverSession(rec, adaptiveCfg, adaptiveRecoveryContextWithWarnContext(adaptiveRecoveryContext{
				sessionKey: "default",
				reason:     adaptiveRecoveryTimer,
				logger:     auditLogger,
				metrics:    m,
			}, opts.warnContext()))
		}

		// Reject JSON-RPC batch requests unconditionally. MCP does not
		// use batch messages, and the response path already drops batch
		// arrays. Forwarding would produce a response blackhole and
		// bypass per-call checks (DoW, chain) due to the aggregated
		// verdict having no Method field.
		trimmedLine := bytes.TrimSpace(line)
		if len(trimmedLine) > 0 && trimmedLine[0] == '[' {
			denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPProtocol, mcpBatchReason, audit.BlockClassProtective)
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked batch request (not supported by MCP)\n", lineNum)
			recordAdaptiveSignal(session.SignalBlock)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:           frame.ID,
				ErrorCode:    -32600,
				ErrorMessage: "pipelock: batch requests are not supported by MCP",
			}, blockedCh)
			continue
		}

		pendingToolCallName := frame.ToolCallName
		pendingMCPMethod := methodToolsCall
		pendingReceiptTarget := pendingToolCallName
		if pendingReceiptTarget == "" && IsA2AMethod(frame.Method) {
			pendingMCPMethod = frame.Method
			pendingReceiptTarget = frame.Method
		}
		pendingActionID := ""
		if pendingReceiptTarget != "" {
			pendingActionID = receipt.NewActionID()
		}
		rpcID := frame.ID
		warnCtx := scanner.DLPWarnContextFromCtx(opts.warnContext())
		warnCtx.Transport = transportMCPStdio
		if policyHash != "" {
			warnCtx.PolicyHash = policyHash
		}
		stdioInputCtx := scanner.WithDLPWarnContext(opts.warnContext(), warnCtx)
		var preRedactionDLP []scanner.TextDLPMatch
		if redactionCfg.Matcher != nil {
			originalVerdict := scanRequestForAgent(stdioInputCtx, line, sc, action, onParseError, opts.addressProtectionAgent())
			if !originalVerdict.Clean && originalVerdict.Error == "" && preRedactionBlock(originalVerdict, action) {
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked (%s)\n", lineNum, joinInputVerdictReasons(originalVerdict))
				denialAudit = mcpInputBlockAudit(originalVerdict)
				recordAdaptiveSignal(session.SignalBlock)
				if pendingActionID != "" && (receiptEmitter != nil || opts.ReceiptGroup != nil) {
					layer, pattern, severity := contentScanAttribution(originalVerdict)
					if _, emitErr := opts.emitReceiptDecision(MCPDecision{
						Receipt: opts.withReceiptPolicyHash(receipt.EmitOpts{
							ActionID:  pendingActionID,
							Verdict:   config.ActionBlock,
							Layer:     layer,
							Pattern:   pattern,
							Severity:  severity,
							Transport: opts.Transport,
							Target:    pendingReceiptTarget,
							MCPMethod: pendingMCPMethod,
							ToolName:  pendingToolCallName,
						}),
					}); emitErr != nil {
						logReceiptEmitFailure(logW, emitErr, opts.requireReceipts(), config.ActionBlock)
					}
				}
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             originalVerdict.ID,
					IsNotification: isRPCNotification(originalVerdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked", lineNum),
					ErrorCode:      -32001,
					ErrorMessage:   "pipelock: request blocked by MCP input scanning",
					ErrorData:      mcpBlockReasonData(mcpScannerBlockReason(originalVerdict, policy.Verdict{}, false)),
				}, blockedCh)
				continue
			}
			// Not blocked before redaction: remember the pre-redaction DLP
			// findings so evidence survives if redaction scrubs them and the
			// post-redaction rescan is clean (see restoreRedactedDLPEvidence).
			if originalVerdict.Error == "" {
				preRedactionDLP = originalVerdict.Matches
			}
		}
		rewrittenLine, redactionReport, redactErr := applyMCPToolCallRedactionWithConfig(line, redactionCfg)
		if redactErr != nil {
			denialAudit = mcpInputGateBlockAudit(scanner.AuditRedaction, mcpRedactionReason, mcpRedactionBlockClass(redactErr))
			reason := redactErr.Error()
			var blockErr *redact.BlockError
			if errors.As(redactErr, &blockErr) {
				reason = "tool arguments redaction blocked: " + string(blockErr.Reason)
			}
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s\n", lineNum, reason)
			recordAdaptiveSignal(session.SignalBlock)
			if pendingActionID != "" && (receiptEmitter != nil || opts.ReceiptGroup != nil) {
				layer, pattern, severity := redactionBlockAttribution(redactErr)
				if _, emitErr := opts.emitReceiptDecision(MCPDecision{
					Receipt: opts.withReceiptPolicyHash(receipt.EmitOpts{
						ActionID:         pendingActionID,
						Verdict:          config.ActionBlock,
						Layer:            layer,
						Pattern:          pattern,
						Severity:         severity,
						RedactionProfile: redactionCfg.Profile,
						Transport:        opts.Transport,
						Target:           pendingReceiptTarget,
						MCPMethod:        pendingMCPMethod,
						ToolName:         pendingToolCallName,
					}),
				}); emitErr != nil {
					logReceiptEmitFailure(logW, emitErr, opts.requireReceipts(), config.ActionBlock)
				}
			}
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             rpcID,
				IsNotification: isRPCNotification(rpcID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redaction)", lineNum),
				ErrorCode:      -32001,
				ErrorMessage:   "pipelock: request blocked by MCP redaction",
			}, blockedCh)
			continue
		}
		line = rewrittenLine
		// Redaction may have rewritten argument values; re-parse so
		// downstream gates (DoW, taint) see the redacted args. ID,
		// Method, and ToolCallName are invariant under redaction but
		// re-parsing keeps the frame the single source of truth.
		frame = ParseMCPFrame(line)

		// Evaluate every configured gate in one pass. The helper returns
		// a composite verdict and the first gate that short-circuited,
		// preserving per-gate block semantics and stdio's gate ordering
		// (policy before DoW, two-phase binding around DoW, frozen tool
		// between DoW and chain, taint last).
		scanEnabled := !opts.stdioInputScanDisabled
		eval := evaluateMCPInputGatesStdio(stdioInputCtx, frame, line, trimmedLine, bindingCfg, opts, action, onParseError, scanEnabled)
		// Preserve cross-agent exposure evidence. Only an enforced denial or
		// indeterminate risk state contributes enforcement points.
		if eval.CrossAgentEscalate {
			recordAdaptiveSignal(eval.CrossAgentObservation.AdaptiveSignal(eval.BlockingGate != ""))
		}
		verdict := eval.ContentVerdict
		// Redaction evidence floor: if redaction scrubbed a pre-redaction DLP
		// finding and the post-redaction rescan is clean, restore the finding
		// as a warn so the request forwards scrubbed but the match is still
		// recorded. Feeding it back into eval keeps the receipt attribution and
		// the downstream reasons consistent with the restored verdict.
		verdict = restoreRedactedDLPEvidence(verdict, preRedactionDLP, redactionReport, action)
		if verdict.RedactedDLPOnly {
			eval.ContentVerdict = verdict
		}
		policyVerdict := eval.PolicyVerdict
		taintDecision := eval.TaintDecision
		bindingAction := eval.BindingAction
		bindingReason := eval.BindingReason
		chainAction := eval.ChainAction
		chainReason := eval.ChainReason

		var toolCallName string
		if verdict.Method == methodToolsCall {
			toolCallName = frame.ToolCallName
		}
		enforcementTarget := toolCallName
		if enforcementTarget == "" {
			enforcementTarget = eval.EnforcementIdentity
		}
		enforcementKind := "tools/call"
		if toolCallName == "" && enforcementTarget != "" {
			enforcementKind = "mcp method"
		}
		baselineIdentity := mcpFrameBaselineIdentity(frame)
		captureActionClass := captureMCPFrameActionClass(enforcementTarget, verdict.Method, mcpFrameCallableArgs(frame))

		// Session binding side effects. Fire the diagnostic log and
		// capture observe for every binding violation regardless of
		// which gate short-circuits later, preserving the pre-refactor
		// ordering where binding observes run before frozen/chain/
		// parse-error/taint have had a chance to fire.
		if bindingReason != "" {
			switch bindingReason {
			case bindingReasonBatchRequest:
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: batch request with session binding active\n", lineNum)
			case bindingReasonMissingToolName:
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: tools/call missing params.name\n", lineNum)
			case bindingReasonNoBaseline:
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s %q before baseline established\n", lineNum, enforcementKind, enforcementTarget)
			case bindingReasonUnknownTool:
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s %q not in session baseline\n", lineNum, enforcementKind, enforcementTarget)
			}
			obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
				Subsurface:        "session_binding",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
				Request: capture.CaptureRequest{
					ToolName:  enforcementTarget,
					MCPMethod: verdict.Method,
					RPCID:     captureRPCID(verdict.ID),
				},
				RawFindings: []capture.Finding{{
					Kind:       capture.KindSessionBinding,
					ToolName:   enforcementTarget,
					PolicyRule: bindingReason,
					Action:     bindingAction,
				}},
				EffectiveAction: bindingAction,
				Outcome:         captureOutcome(bindingAction, false),
			})
		}

		// Chain side effects. Log, audit, and capture observe on every
		// match, block and warn alike. The block-dispatch switch below
		// handles the block-specific adaptive signal + BlockedRequest;
		// warn matches fall through into the effective-action merge
		// below with chainAction / chainReason populated.
		if eval.ChainMatched {
			_, _ = fmt.Fprintf(logW, "pipelock: chain detected: %s (severity=%s, action=%s)\n",
				eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction)
			if auditLogger != nil {
				auditLogger.LogChainDetection(eval.ChainPatternName, eval.ChainSeverity, eval.ChainAction, enforcementTarget, "default")
			}
			obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
				Subsurface:        "chain_detection",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
				Request: capture.CaptureRequest{
					ToolName:  enforcementTarget,
					MCPMethod: verdict.Method,
					RPCID:     captureRPCID(verdict.ID),
				},
				RawFindings: []capture.Finding{{
					Kind:     capture.KindChainDetection,
					Chain:    eval.ChainPatternName,
					Severity: eval.ChainSeverity,
					Action:   eval.ChainAction,
				}},
				EffectiveAction: eval.ChainAction,
				Outcome:         captureOutcome(eval.ChainAction, false),
			})
		}

		// Pre-generate actionID for receipt-bearing calls. In required-receipt
		// mode, the ordinary MCP handshake is also mediated action evidence:
		// tools/list has the established read classification and initialize is
		// represented by the existing unclassified action type. Neither gains an
		// envelope because envelopes remain limited to tools/call.
		actionID := ""
		receiptTarget := toolCallName
		receiptBearingMethod := verdict.Method == methodToolsCall ||
			(opts.requireReceipts() && isRequiredReceiptMetadataMethod(verdict.Method))
		if receiptTarget == "" && IsA2AMethod(verdict.Method) {
			receiptTarget = verdict.Method
			receiptBearingMethod = true
		}
		if receiptTarget == "" && isRequiredReceiptMetadataMethod(verdict.Method) {
			receiptTarget = verdict.Method
		}
		if receiptBearingMethod {
			if pendingActionID != "" {
				actionID = pendingActionID
			} else {
				actionID = receipt.NewActionID()
			}
		}
		receiptEmitted := false
		redirectReceiptActionID := ""
		receiptDecisionPhase := ""
		receiptDeferID := ""
		receiptResolutionPolicy := ""
		receiptResolutionSource := ""
		receiptSessionID := ""
		receiptSessionIDOriginal := ""
		receiptLayerOverride := ""
		receiptPatternOverride := ""
		receiptSeverityOverride := ""
		// Keep the admission choice for the later response outcome. Blocked
		// requests also choose once when their first receipt is emitted.
		var receiptShard receipt.EmitOpts

		emitToolReceipt := func(receiptVerdict string, contractGate ...mcpContractGateOutput) error {
			if verdict.Method != methodToolsCall && receiptVerdict == config.ActionAllow && !opts.requireReceipts() {
				return nil
			}
			// Delegate to the shared helper so stdio and HTTP/WS emit
			// tool receipts through the same EmitMCPDecision entry.
			layer, pattern, severity := pickAttribution(eval)
			if receiptLayerOverride != "" {
				layer, pattern, severity = receiptLayerOverride, receiptPatternOverride, receiptSeverityOverride
			}
			requireReceipts := opts.requireReceipts()
			if opts.ReceiptGroup != nil && opts.ReceiptGroup.Shards != nil && !receiptShard.ShardSelected {
				receiptShard = opts.ReceiptGroup.Shards.Admit(receiptShard)
			}
			receiptOpts := mcpToolReceiptOpts{
				ProxyOpts:         opts,
				Shard:             receiptShard,
				Log:               logW,
				Transport:         opts.Transport,
				RedactionProfile:  redactionCfg.Profile,
				ActionID:          actionID,
				MCPMethod:         verdict.Method,
				ToolName:          toolCallName,
				Target:            receiptTarget,
				Verdict:           receiptVerdict,
				Layer:             layer,
				Pattern:           pattern,
				Severity:          severity,
				Decision:          taintDecision,
				Report:            redactionReport,
				RequireReceipts:   requireReceipts,
				RequireReceipt:    (requireReceipts && receiptVerdict != config.ActionBlock) || receiptVerdict == config.ActionDefer,
				DecisionPhase:     receiptDecisionPhase,
				DeferID:           receiptDeferID,
				ResolutionPolicy:  receiptResolutionPolicy,
				ResolutionSource:  receiptResolutionSource,
				SessionID:         receiptSessionID,
				SessionIDOriginal: receiptSessionIDOriginal,
			}
			if redirectReceiptActionID != "" && receiptVerdict == config.ActionBlock {
				receiptOpts.ParentActionID = redirectReceiptActionID
				receiptOpts.ActionID = receipt.NewActionID()
			}
			if len(contractGate) > 0 {
				receiptOpts.ContractGate = &contractGate[0]
			}
			return emitMCPToolReceipt(receiptOpts)
		}

		logTaintDecision := func() {
			if auditLogger == nil {
				return
			}
			decision := taintDecision
			if eval.TaintAuditDecisionSet {
				decision = eval.TaintAuditDecision
			}
			auditLogger.LogTaintDecision(
				mustMCPAuditContext(auditLogger, "MCP", enforcementTarget),
				audit.TaintDecision{
					TaintLevel:  decision.Risk.Level.String(),
					ActionClass: decision.ActionClass.String(),
					Sensitivity: decision.Sensitivity.String(),
					Authority:   decision.Authority.String(),
					Decision:    decision.Result.Decision.String(),
					Reason:      decision.Result.Reason,
					SourceURL:   decision.Risk.SecurityOriginURL(),
					SourceKind:  decision.Risk.SecurityOriginKind(),
				},
			)
		}

		// DoW diagnostic log. Runs on any !allowed outcome (block or
		// warn). Held in a local so the block-dispatch case below can
		// reuse it verbatim as the BlockedRequest.LogMessage.
		var dowLogMsg string
		if !eval.DoWAllowed && eval.DoWAction != "" {
			dowLogMsg = fmt.Sprintf("pipelock: input line %d: %s %q DoW %s: %s (%s)",
				lineNum, enforcementKind, enforcementTarget, eval.DoWAction, eval.DoWReason, eval.DoWBudgetType)
			_, _ = fmt.Fprintln(logW, dowLogMsg)
		}

		// Block dispatch on the first gate that short-circuited. Per
		// gate: audit + metrics + adaptive-signal + BlockedRequest.
		// The response shape (JSON-RPC error code, LogMessage) stays
		// here because it is transport-specific.
		switch eval.BlockingGate {
		case blockingGateA2ABody:
			class, reason := mcpA2AGateAudit(eval.A2AResult)
			denialAudit = mcpInputGateBlockAudit(scanner.AuditA2AScan, reason, class)
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: a2a input blocked (%s)\n", lineNum, eval.A2AResult.Reason)
			switch {
			case eval.A2AResult.IsAdaptiveNeutral():
			case eval.A2AResult.IsConfigMismatch():
				recordAdaptiveFinding(session.SignalNearMiss, "a2a", eval.A2AResult.Reason)
			default:
				recordAdaptiveFinding(session.SignalBlock, "a2a", eval.A2AResult.Reason)
			}
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (a2a input scanning)", lineNum),
				ErrorCode:      -32001,
				ErrorMessage:   "pipelock: request blocked by A2A input scanning",
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateAirlockHard, blockingGateAirlockMissing:
			blockMessage := mcpAirlockDiagnostic(eval, opts, rec, logW)
			airlockMsg := fmt.Sprintf("pipelock: input line %d: %s: %q", lineNum, blockMessage, enforcementTarget)
			_, _ = fmt.Fprintln(logW, airlockMsg)
			if auditLogger != nil {
				auditLogger.LogAirlockDenyReason(audit.AirlockDenyOptions{
					SessionKey: "default",
					Tier:       eval.AirlockTier,
					Transport:  firstNonEmpty(opts.Transport, transportMCPStdio),
					Method:     methodToolsCall,
					Reason:     eval.AirlockReason,
					RequestID:  canonicalID(verdict.ID),
				})
			}
			if m != nil {
				m.RecordAirlockDenial(eval.AirlockTier, "mcp", methodToolsCall)
			}
			sendMCPDenial(opts, mcpAirlockDenialAudit(), BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     airlockMsg,
				ErrorCode:      -32001,
				ErrorMessage:   blockMessage,
				ErrorData:      mcpBlockReasonData(blockreason.AirlockActive),
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateDoW:
			denialAudit = mcpDoWDenialAudit(opts, enforcementTarget, eval.DoWReason)
			recordDoWMetric(m, config.ActionBlock, opts)
			recordAdaptiveFinding(session.SignalBlock, scanner.ScannerDenialOfWallet, eval.DoWReason)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     dowLogMsg,
				ErrorCode:      -32600,
				ErrorMessage:   "pipelock: " + eval.DoWReason,
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateFrozenTool:
			frozenMsg := fmt.Sprintf("pipelock: input line %d: tools/call %q blocked by frozen tool inventory", lineNum, eval.FrozenToolName)
			_, _ = fmt.Fprintln(logW, frozenMsg)
			denialAudit = mcpFrozenDenialAudit(opts, eval.FrozenToolName)
			if m != nil {
				m.RecordBlocked("mcp", "frozen_tool", 0, "")
			}
			recordAdaptiveSignal(session.SignalBlock)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     frozenMsg,
				ErrorCode:      -32600,
				ErrorMessage:   "pipelock: tool not in frozen inventory",
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateChain:
			denialAudit = mcpChainBlockAudit(eval.ChainPatternName)
			recordAdaptiveFinding(session.SignalBlock, "chain", eval.ChainPatternName)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: chain pattern %q blocked", lineNum, eval.ChainPatternName),
				ErrorCode:      -32004,
				ErrorMessage:   fmt.Sprintf("tool call blocked: chain pattern %q detected", eval.ChainPatternName),
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateParseError:
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: %s\n", lineNum, verdict.Error)
			denialAudit = mcpInputBlockAudit(verdict)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (parse error)", lineNum),
				ErrorCode:      jsonRPCErrorCodeForInputError(verdict.Error),
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		case blockingGateTaintBlock, blockingGateTaintAskDenied:
			logTaintDecision()
			sendMCPDenial(opts, mcpTaintDenialAudit(), BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isRPCNotification(verdict.ID),
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked by taint policy", lineNum),
				ErrorCode:      -32002,
				ErrorMessage:   "pipelock: " + taintDecision.Result.Reason,
			}, blockedCh)
			_ = emitToolReceipt(config.ActionBlock)
			continue
		}

		// Non-blocking warn-level side effects from gates that did not
		// short-circuit. A2A warn records a zero-point observation unless the
		// finding is adaptive-neutral. DoW warn: audit anomaly + observation
		// signal (the diagnostic log already ran above). Taint approved:
		// audit the pre-approval decision so the operator sees the approval
		// happened.
		if !eval.A2AResult.Clean && eval.A2AEffectiveAction != "" && eval.A2AEffectiveAction != config.ActionBlock {
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: a2a input warning (%s)\n", lineNum, eval.A2AResult.Reason)
			if !eval.A2AResult.IsAdaptiveNeutral() {
				recordAdaptiveFinding(session.SignalWarning, "a2a", eval.A2AResult.Reason)
			}
		}
		if !eval.DoWAllowed && eval.DoWAction != "" {
			if auditLogger != nil {
				auditLogger.LogAnomaly(mustMCPDoWAuditContext(auditLogger, enforcementTarget, opts), scanner.ScannerDenialOfWallet, eval.DoWReason, 0)
			}
			recordDoWMetric(m, config.ActionWarn, opts)
			recordAdaptiveFinding(session.SignalWarning, scanner.ScannerDenialOfWallet, eval.DoWReason)
		}
		if eval.TaintApproved {
			logTaintDecision()
		}

		// All clean - forward (with block_all and CEE checks).
		if verdict.Clean && !policyVerdict.Matched && bindingAction == "" && chainAction == "" {
			if baselineIdentity != "" {
				baselineDecision := checkMCPToolCallBaselineAttempt(opts, baselineMetricsRecorder(opts, rec), baselineIdentity)
				switch baselineDecision.Action {
				case config.ActionBlock, config.ActionAsk:
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s)\n",
						lineNum, verdict.Method, baselineDecision.Detail)
					denialAudit = mcpBaselineBlockAudit()
					recordAdaptiveSignal(session.SignalBlock)
					errMsg := ""
					if baselineDecision.Action == config.ActionAsk {
						errMsg = "pipelock: MCP request blocked by behavioral baseline"
					}
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (baseline deviation)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   errMsg,
					}, blockedCh)
					_ = emitToolReceipt(config.ActionBlock)
					continue
				case config.ActionWarn:
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: warning — %s request contains flagged content (%s)\n",
						lineNum, verdict.Method, baselineDecision.Detail)
					recordAdaptiveSignal(session.SignalWarning)
				}
			}
			// block_all enforcement: deny ALL traffic (including clean) when the
			// session is at an escalation level with block_all=true.
			if rec != nil && decide.UpgradeAction("", rec.EscalationLevel(), adaptiveCfg) == config.ActionBlock {
				_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade (clean) -> block (level %s)\n", session.EscalationLabel(rec.EscalationLevel()))
				denialAudit = mcpCleanAdaptiveBlockAudit()
				if m != nil {
					m.RecordAdaptiveUpgrade("", config.ActionBlock, session.EscalationLabel(rec.EscalationLevel()))
				}
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (session deny)", lineNum),
					ErrorCode:      -32001,
					ErrorMessage:   mcpAdaptiveBlockMessage(rec, adaptiveCfg, "session_deny", logW),
				}, blockedCh)
				continue
			}
			// Cross-request exfiltration check on clean outbound messages.
			inspectionMode, fallbackReason, matchedPattern, ceeBlockKind := "", "", "", ""
			var ceeContributors []json.RawMessage
			ceeOpts := ceeRecordMCPOptions{
				denialAudit:    &denialAudit,
				sessionKey:     ceeStdioKey,
				entropyPayload: line,
				frame:          frame,
				cee:            cee,
				sc:             sc,
				logW:           logW,
				logger:         auditLogger,
				inspectionMode: &inspectionMode,
				fallbackReason: &fallbackReason,
				matchedPattern: &matchedPattern,
				blockKind:      &ceeBlockKind,
				contributors:   &ceeContributors,
			}
			if reason := ceeRecordMCP(ceeOpts); reason != "" {
				// Capture: record CEE verdict.
				obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
					Subsurface:        "cee_mcp_stdio",
					Transport:         opts.Transport,
					SessionID:         captureSessionID(opts.Transport),
					SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
					ConfigHash:        opts.captureConfigHash(),
					Profile:           opts.captureProfile(),
					ActionClass:       captureActionClass,
					Request:           capture.CaptureRequest{RPCID: captureRPCID(verdict.ID), CEEContributors: ceeContributors},
					RawFindings: []capture.Finding{{
						Kind:   capture.KindCEE,
						Action: config.ActionBlock,
					}},
					EffectiveAction: config.ActionBlock,
					Outcome:         capture.OutcomeBlocked,
					InspectionMode:  inspectionMode,
					FallbackReason:  fallbackReason,
				})
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: CEE blocked", lineNum),
					ErrorCode:      -32005,
					ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
				}, blockedCh)
				// A method that carries neither a tool call nor required receipt
				// metadata never minted a receipt identity, and the emitter drops
				// a receipt with an empty action ID. Mint one here so a CEE block
				// on any method leaves evidence, exactly as the authorization
				// block below this loop already does.
				if actionID == "" {
					actionID = receipt.NewActionID()
				}
				if receiptTarget == "" {
					receiptTarget = verdict.Method
				}
				receiptLayerOverride = "cross_request"
				receiptPatternOverride = ceeBlockKind
				if matchedPattern != "" {
					receiptPatternOverride = matchedPattern
				}
				receiptSeverityOverride = "critical"
				_ = emitToolReceipt(config.ActionBlock)
				continue
			}
			contractGate, contractErr := evaluateMCPToolGate(frame, config.ActionAllow, false, opts)
			if contractErr != nil {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditContract, mcpContractEvalReason, audit.BlockClassInfrastructureError)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: contract tool-call evaluation failed: %v\n", lineNum, contractErr)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: contract tool-call evaluation failed", lineNum),
					ErrorCode:      -32006,
					ErrorMessage:   "pipelock: contract tool-call evaluation failed",
				}, blockedCh)
				_ = emitToolReceipt(config.ActionBlock)
				continue
			}
			if contractGate.Verdict == config.ActionBlock {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditContract, mcpContractDenyAuditReason, audit.BlockClassProtective)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: contract blocked %s %q (%s)\n", lineNum, enforcementKind, enforcementTarget, contractGate.Reason)
				sendMCPDenial(opts, denialAudit, mcpContractBlockRequest(verdict.ID, contractGate, "pipelock: request blocked by live-lock contract"), blockedCh)
				_ = emitToolReceipt(config.ActionBlock, contractGate)
				continue
			}
			if err := authorizeMCP(stdioInputCtx, authorityRef, authorityCarrierErr, frame, opts); err != nil {
				if actionID == "" {
					actionID = receipt.NewActionID()
				}
				if receiptTarget == "" {
					receiptTarget = verdict.Method
				}
				receiptLayerOverride, receiptPatternOverride, receiptSeverityOverride = authorityReceiptAttribution()
				_ = emitToolReceipt(config.ActionBlock, contractGate)
				sendMCPDenial(opts, mcpAuthorityDenialAudit(), *authorityBlockedRequest(frame), blockedCh)
				continue
			}
			fwdLine := line
			if verdict.Method == methodToolsCall {
				buildOpts := envelope.BuildOpts{
					ActionID:       actionID,
					Action:         string(receipt.ClassifyMCPTool(toolCallName, verdict.Method)),
					Verdict:        config.ActionAllow,
					SessionTaint:   taintDecision.Risk.Level.String(),
					TaskID:         taintDecision.Task.CurrentTaskID,
					AuthorityKind:  taintDecision.Authority.String(),
					RequiresReauth: taintDecision.RequiresReauth,
				}
				var emitErr error
				fwdLine, emitErr = emitMCPEnvelopeDecision(envelopeEmitter, MCPDecision{
					Envelope:   &buildOpts,
					InboundMsg: line,
				})
				if emitErr != nil {
					denialAudit = mcpInputGateBlockAudit(scanner.AuditMediationEnvelope, mcpEnvelopeReason, audit.BlockClassInfrastructureError)
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     "mediation envelope injection failed",
						ErrorCode:      -32002,
						ErrorMessage:   "pipelock: mediation envelope injection failed",
					}, blockedCh)
					continue
				}
			}
			receiptVerdict := config.ActionAllow
			if isRequiredReceiptHandshakeNotification(verdict.Method, verdict.ID) {
				receiptVerdict = config.ActionForward
			}
			if err := emitToolReceipt(receiptVerdict, contractGate); err != nil {
				denialAudit = mcpOperationalBlockAudit(scanner.AuditReceiptEmission, "mcp_input", mcpReceiptEmissionReason)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     "receipt emission failed",
					ErrorCode:      -32007,
					ErrorMessage:   requiredReceiptFailureMessage(err),
					ErrorData:      mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
				}, blockedCh)
				continue
			}
			// Track request ID immediately before forwarding so response-side
			// can validate without leaving stale state when a required
			// receipt fails before the request is written.
			if isTrackableRequest(fwdLine, verdict.ID) && opts.requireReceipts() && actionID != "" {
				outcomeReceipt := opts.withReceiptPolicyHash(receipt.EmitOpts{
					ActionID:            actionID,
					Verdict:             config.ActionAllow,
					Transport:           opts.Transport,
					Target:              receiptTarget,
					MCPMethod:           verdict.Method,
					ToolName:            toolCallName,
					SessionTaintLevel:   taintDecision.Risk.Level.String(),
					SessionContaminated: taintDecision.Risk.Contaminated,
					RecentTaintSources:  taintDecision.Risk.Sources,
					SessionTaskID:       taintDecision.Task.CurrentTaskID,
					SessionTaskLabel:    taintDecision.Task.CurrentTaskLabel,
					AuthorityKind:       taintDecision.Authority.String(),
					TaintDecision:       taintDecision.Result.Decision.String(),
					TaintDecisionReason: taintDecision.Result.Reason,
					TaskOverrideApplied: taintDecision.TaskOverrideApplied,
					PolicyHash:          policyHash,
				})
				outcomeReceipt = mcpWithContractReceipt(outcomeReceipt, contractGate)
				outcomeReceipt.ShardIndex = receiptShard.ShardIndex
				outcomeReceipt.ShardSelected = receiptShard.ShardSelected
				tracker.TrackOutcome(verdict.ID, TrackedRequestOutcome{Receipt: outcomeReceipt, Method: verdict.Method})
			} else if isTrackableRequest(fwdLine, verdict.ID) {
				tracker.TrackRequest(verdict.ID, verdict.Method)
			}
			if err := forwardMessage(fwdLine); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			commitMCPToolCall(baselineMetricsRecorder(opts, rec), baselineIdentity)
			if !hadAdaptiveFinding {
				recordCleanSession(rec, adaptiveCfg, true, adaptiveRecoveryContextWithWarnContext(adaptiveRecoveryContext{
					sessionKey: "default",
					reason:     adaptiveRecoveryClean,
					requestID:  canonicalID(verdict.ID),
					logger:     auditLogger,
					metrics:    m,
				}, stdioInputCtx))
			}
			continue
		}

		// Build combined reasons from content scan, policy, and binding.
		reasons := inputVerdictReasons(verdict)
		for _, r := range policyVerdict.Rules {
			reasons = append(reasons, "policy:"+r)
		}
		reasons = append(reasons, policyVerdict.Notes...)
		if bindingReason != "" {
			reasons = append(reasons, bindingReason)
		}
		if chainReason != "" {
			reasons = append(reasons, chainReason)
		}
		reasonStr := joinStrings(reasons)

		method := verdict.Method
		if method == "" {
			method = patternUnknown
		}

		// Determine effective action: strictest of content scan, policy, and binding.
		// mergeAction handles the initial empty state correctly (empty = no action yet).
		effectiveAction := ""
		mergeAction := func(cur, next string) string {
			if cur == "" {
				return next
			}
			return policy.StricterAction(cur, next)
		}
		if !verdict.Clean {
			effectiveAction = inputVerdictEffectiveAction(verdict, action)
		}
		if policyVerdict.Matched {
			effectiveAction = mergeAction(effectiveAction, policyVerdict.Action)
		}
		if bindingAction != "" {
			effectiveAction = mergeAction(effectiveAction, bindingAction)
		}
		if chainAction != "" {
			effectiveAction = mergeAction(effectiveAction, chainAction)
		}

		isNotification := isRPCNotification(verdict.ID)

		// Determine error response fields based on what triggered the block.
		isPolicyOnly := verdict.Clean && policyVerdict.Matched
		errCode := 0 // default: -32001 (content scan)
		errMsg := "" // default message
		if isPolicyOnly {
			errCode = -32002 // policy-specific error code
			errMsg = errPolicyBlocked
		}

		// Escalation upgrade: may promote warn/ask to block for elevated sessions.
		entropyOnlyDecision := verdict.IsEntropyOnly() && !policyVerdict.Matched && bindingAction == "" && chainAction == ""
		originalAction := effectiveAction
		scoringAction := originalAction
		numberOnlyDecision := verdict.IsInformationalCardRuns() && !policyVerdict.Matched && bindingAction == "" && chainAction == ""
		if rec != nil && !entropyOnlyDecision && !numberOnlyDecision {
			effectiveAction = decide.UpgradeAction(effectiveAction, rec.EscalationLevel(), adaptiveCfg)
		}
		if effectiveAction != originalAction {
			errMsg = mcpAdaptiveBlockMessage(rec, adaptiveCfg, "mcp_input", logW)
			_, _ = fmt.Fprintf(logW, "pipelock: adaptive upgrade %s -> %s (level %s)\n", originalAction, effectiveAction, session.EscalationLabel(rec.EscalationLevel()))
			if m != nil {
				m.RecordAdaptiveUpgrade(originalAction, effectiveAction, session.EscalationLabel(rec.EscalationLevel()))
			}
		}

		baselineAction := ""
		if baselineIdentity != "" {
			baselineDecision := checkMCPToolCallBaselineAttempt(opts, baselineMetricsRecorder(opts, rec), baselineIdentity)
			if baselineDecision.Action != "" {
				baselineAction = baselineDecision.Action
				reasons = append(reasons, baselineDecision.Detail)
				// Recompute so the block/warn reason includes the baseline
				// deviation detail (reasonStr was built before this append).
				reasonStr = joinStrings(reasons)
				effectiveAction = mergeAction(effectiveAction, baselineDecision.Action)
				scoringAction = mergeAction(scoringAction, baselineDecision.Action)
				if baselineDecision.Action == config.ActionBlock || baselineDecision.Action == config.ActionAsk {
					// Informational card observations cannot erase an independent baseline refusal.
					numberOnlyDecision = false
				}
				if baselineDecision.Action == config.ActionAsk {
					errCode = -32001
					errMsg = "pipelock: MCP request blocked by behavioral baseline"
				}
			}
		}

		redirectSucceeded := false
		var contractGateForReceipt *mcpContractGateOutput
		contentBlock := inputBlockedByContent(verdict, action)
		switch effectiveAction {
		case config.ActionBlock:
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s)\n",
				lineNum, method, reasonStr)
			denialAudit = mcpInputDecisionBlockAudit(verdict, contentBlock, policyVerdict, bindingAction, chainAction, eval.ChainPatternName, baselineAction)
			blockReason := mcpScannerBlockReason(verdict, policyVerdict, chainAction != "")
			if bindingReason != "" && bindingAction == config.ActionBlock {
				blockReason = blockreason.SessionBinding
				if errMsg == "" {
					errMsg = "pipelock: " + bindingReason
				}
			}
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked", lineNum),
				ErrorCode:      errCode,
				ErrorMessage:   errMsg,
				ErrorData:      mcpBlockReasonData(blockReason),
			}, blockedCh)
		case config.ActionRedirect:
			// Batch requests cannot be redirected element-by-element.
			// Fail closed: block the entire batch.
			trimmed := bytes.TrimSpace(line)
			if len(trimmed) > 0 && trimmed[0] == '[' {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPRedirect, mcpRedirectBatchReason, audit.BlockClassProtective)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked batch request (%s) [redirect not supported for batches]\n",
					lineNum, reasonStr)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (batch redirect)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}, blockedCh)
				break
			}
			profile, ok := policyCfg.RedirectProfiles[policyVerdict.RedirectProfile]
			if !ok {
				// Profile not found - fail closed to block.
				denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPRedirect, mcpRedirectProfileReason, audit.BlockClassConfigMismatch)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [redirect profile %q not found]\n",
					lineNum, method, reasonStr, policyVerdict.RedirectProfile)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect profile missing)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}, blockedCh)
				break
			}
			toolName, toolArgs := extractToolCallFields(line)
			policyRuleName := ""
			if len(policyVerdict.Rules) > 0 {
				policyRuleName = policyVerdict.Rules[0]
			}
			// A redirect handler can execute the action itself. Required receipt
			// admission must precede the handler, not just its synthetic response.
			if opts.requireReceipts() {
				if err := emitToolReceipt(config.ActionRedirect); err != nil {
					denialAudit = mcpOperationalBlockAudit(scanner.AuditReceiptEmission, "mcp_input", mcpReceiptEmissionReason)
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID: verdict.ID, IsNotification: isNotification,
						LogMessage: "receipt emission failed", ErrorCode: -32007,
						ErrorMessage: requiredReceiptFailureMessage(err),
						ErrorData:    mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
					}, blockedCh)
					continue
				}
				receiptEmitted = true
				redirectReceiptActionID = actionID
			}
			result := executeRedirect(profile, policyVerdict.RedirectProfile, verdict.ID, toolArgs, policyRuleName, redirectRT)
			// Determine final outcome before audit logging so the event
			// reflects the actual result delivered to the client.
			finalResult := "blocked"
			if result.Success {
				// Scan redirect handler output for prompt injection AND DLP before
				// sending to client. Handler output is untrusted.
				scanVerdict := scanResponseOpts(result.Response, sc, ResponseScanOptions{Context: stdioInputCtx}, false)
				stdioWarnCtxMeta := scanner.DLPWarnContextFromCtx(stdioInputCtx)
				stdioWarnCtxMeta.Transport = transportMCPStdio
				stdioWarnCtxMeta.Method = mcpWarnMethod
				stdioWarnCtxMeta.Resource = mcpWarnResource(verdict.Method, line)
				if policyHash != "" {
					stdioWarnCtxMeta.PolicyHash = policyHash
				}
				stdioWarnCtx := scanner.WithDLPWarnContext(stdioInputCtx, stdioWarnCtxMeta)
				dlpResult := sc.ScanTextForDLP(stdioWarnCtx, string(result.Response))
				finalResponseVerdict := scanVerdict
				finalResponseVerdict.DLPMatches = append(finalResponseVerdict.DLPMatches, dlpResult.Matches...)
				finalResponseVerdict.Clean = scanVerdict.Clean && dlpResult.Clean
				responseAction := config.ActionRedirect
				if !finalResponseVerdict.Clean {
					responseAction = config.ActionBlock
				}
				// Capture: record redirect output scan verdict.
				obs.ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
					Subsurface:        "response_redirect_output",
					Transport:         opts.Transport,
					SessionID:         captureSessionID(opts.Transport),
					SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
					ConfigHash:        opts.captureConfigHash(),
					Profile:           opts.captureProfile(),
					ActionClass:       captureActionClass,
					Request:           capture.CaptureRequest{RPCID: captureRPCID(verdict.ID)},
					TransformKind:     capture.TransformRedirectOutput,
					WirePayload:       result.Response,
					RawFindings:       append(responseMatchesToFindings(finalResponseVerdict.Matches, responseAction), dlpMatchesToFindingsWithAction(finalResponseVerdict.DLPMatches, responseAction)...),
					EffectiveAction:   responseAction,
					Outcome:           captureOutcome(responseAction, finalResponseVerdict.Clean),
				})
				if !finalResponseVerdict.Clean {
					effectiveAction = config.ActionBlock
					receiptEmitted = false
					receiptLayerOverride = mcpReceiptLayerResponse
					receiptPatternOverride, receiptSeverityOverride = redirectResponseAttribution(finalResponseVerdict)
				}
				if !scanVerdict.Clean {
					denialAudit = mcpRedirectOutputBlockAudit(scanner.AuditMCPRedirectOutputInjection, mcpRedirectOutputInjectionReason)
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked redirect response (injection detected in handler output)\n", lineNum)
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isNotification,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect output injection)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: redirect handler output blocked by response scanning",
					}, blockedCh)
				} else if !dlpResult.Clean {
					denialAudit = mcpRedirectOutputBlockAudit(scanner.AuditMCPRedirectOutputDLP, mcpRedirectOutputDLPReason)
					pattern := patternUnknown
					if len(dlpResult.Matches) > 0 {
						pattern = dlpResult.Matches[0].PatternName
					}
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked redirect response (DLP match in handler output: %s)\n", lineNum, pattern)
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isNotification,
						LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect output DLP)", lineNum),
						ErrorCode:      -32001,
						ErrorMessage:   "pipelock: redirect handler output blocked by DLP scanning",
					}, blockedCh)
				} else {
					finalResult = "redirected"
					redirectSucceeded = true
					_, _ = fmt.Fprintf(logW, "pipelock: input line %d: redirected %s request via profile %q (%dms)\n",
						lineNum, method, policyVerdict.RedirectProfile, result.LatencyMs)
					sendMCPSynthetic(mcpSyntheticResult{
						notification: isNotification,
						logMessage:   fmt.Sprintf("pipelock: input line %d: redirected", lineNum),
						response:     result.Response,
					}, blockedCh)
				}
			} else {
				// Redirect handler failed - fall through to block (fail-closed).
				denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPRedirect, mcpRedirectHandlerReason, audit.BlockClassInfrastructureError)
				effectiveAction = config.ActionBlock
				receiptEmitted = false
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [redirect failed: %s]\n",
					lineNum, method, reasonStr, result.Error)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (redirect failed)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   errPolicyBlocked,
				}, blockedCh)
			}
			if auditLogger != nil {
				auditLogger.LogToolRedirect(audit.ToolRedirectEvent{
					ToolName:        toolName,
					ArgsDigest:      argsDigest(toolArgs),
					RedirectProfile: policyVerdict.RedirectProfile,
					RedirectReason:  profile.Reason,
					PolicyRule:      policyRuleName,
					Result:          finalResult,
					LatencyMs:       result.LatencyMs,
				})
			}
		case config.ActionDefer:
			manager := opts.deferManager()
			if err := deferred.ValidateAction(opts.Transport, config.ActionDefer); err != nil {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPDefer, mcpDeferUnsupportedReason, audit.BlockClassConfigMismatch)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [%v]\n",
					lineNum, method, reasonStr, err)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (defer unsupported)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   err.Error(),
				}, blockedCh)
				effectiveAction = config.ActionBlock
				break
			}
			if manager == nil || !manager.Enabled() {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditMCPDefer, mcpDeferDisabledReason, audit.BlockClassConfigMismatch)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [defer manager disabled]\n",
					lineNum, method, reasonStr)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (defer disabled)", lineNum),
					ErrorCode:      -32002,
					ErrorMessage:   "pipelock: defer is disabled",
				}, blockedCh)
				effectiveAction = config.ActionBlock
				break
			}
			receiptDecisionPhase = receipt.DecisionPhaseDefer
			receiptDeferID = actionID
			receiptResolutionPolicy = deferred.ReceiptPolicyString(manager.Policy(), policyVerdict.ResolutionPolicy)
			receiptSessionID = captureSessionID(opts.Transport)
			receiptSessionIDOriginal = captureSessionIDOriginal(opts.Transport)
			if err := emitToolReceipt(config.ActionDefer); err != nil {
				denialAudit = mcpOperationalBlockAudit(scanner.AuditReceiptEmission, "mcp_input", mcpReceiptEmissionReason)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isNotification,
					LogMessage:     "receipt emission failed",
					ErrorCode:      -32007,
					ErrorMessage:   "pipelock: receipt emission failed",
					ErrorData:      mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
				}, blockedCh)
				effectiveAction = config.ActionBlock
				break
			}
			receiptEmitted = true
			heldLine := append([]byte(nil), line...)
			heldID := append(json.RawMessage(nil), verdict.ID...)
			heldNotification := isNotification
			heldToolName := toolCallName
			heldBaselineIdentity := baselineIdentity
			heldAuthorityRef := authorityRef
			heldAuthorityCarrierErr := authorityCarrierErr
			heldAuthorityFrame := frame
			_, deferToolArgs := extractToolCallFields(line)
			argDigest := argsDigest(deferToolArgs)
			receiptSettle := &deferredReceiptSettlement{}
			var terminalSlot mcpDeferredTerminal
			// A receipt or journal failure can downgrade a prepared allow to
			// deny. Release its upstream write lock and send claim before the
			// finalizer's synchronous audit sinks or downstream delivery can
			// block unrelated upstream work. OnceFunc also makes the manager's
			// deferred cleanup safe after this early denial cleanup.
			var finishDeniedRelease func()
			holdErr := manager.Hold(deferred.HeldAction{
				DeferID:       actionID,
				ActionID:      actionID,
				ShardIndex:    receiptShard.ShardIndex,
				ShardSelected: receiptShard.ShardSelected,
				Target:        heldToolName,
				Reason:        reasonStr,
				Surface:       opts.Transport,
				Method:        verdict.Method,
				SizeBytes:     len(heldLine),
				RulePolicy:    policyVerdict.ResolutionPolicy,
				Payload:       append([]byte(nil), heldLine...),
				ArgDigest:     argDigest,
				Authority: deferred.AuthoritySnapshot{
					SessionID:         receiptSessionID,
					SessionIDOriginal: receiptSessionIDOriginal,
				},
				BeforeAllow: func() (func(), bool) {
					return deferredReleasePrecheck(opts, deferredGeneration)
				},
				// Prepare settles the final decision before the manager
				// journals it, so the journal and the receipt agree. On an
				// allow it returns holding forwardMu and the kill-switch
				// claim; the manager releases both with defer after Resolve
				// returns or panics.
				Prepare: func(res deferred.Resolution) (deferred.Resolution, func()) {
					if res.FinalDecision == config.ActionAllow {
						if authErr := authorizeMCP(stdioInputCtx, heldAuthorityRef, heldAuthorityCarrierErr, heldAuthorityFrame, opts); authErr != nil {
							res.FinalDecision = config.ActionBlock
							res.ResolutionSource = deferred.SourceAuthority
							res.Reason = "authority verification failed"
						}
					}
					if res.ResolutionSource == deferred.SourceKillSwitch {
						markDeferredKillSwitch(&res)
					}
					if res.FinalDecision != config.ActionAllow {
						return res, nil
					}
					// Irreversible release boundary. Take the writer lock
					// first so no wait for another write sits between the
					// kill-switch claim and this write; see
					// claimDeferredRelease for the ordering argument.
					prepared, finish := lockAndClaimDeferredRelease(&forwardMu, opts, deferredGeneration, res)
					if finish != nil {
						finish = sync.OnceFunc(finish)
						finishDeniedRelease = finish
					}
					prepared = receiptSettle.probeAllow(opts, prepared)
					return prepared, finish
				},
				// The release receipt is written while the journal shows the
				// release as pending: the allow first, then a corrective block
				// if the journal cannot record the allow as final.
				AfterJournal: func(res deferred.Resolution) error {
					return receiptSettle.commitAllow(opts, logW, res)
				},
				Resolve: func(res deferred.Resolution) {
					denialOpts := opts
					denialOpts.denialTerminal = &terminalSlot
					denialAudit := mcpDeferredDenialAudit(res)
					authorityDenied := res.ResolutionSource == deferred.SourceAuthority
					if emitErr := receiptSettle.ensure(opts, logW, res); emitErr != nil {
						if finishDeniedRelease != nil {
							finishDeniedRelease()
						}
						if res.FinalDecision == config.ActionAllow {
							denialAudit = mcpReceiptMcpInputDenialAudit()
						}
						if heldNotification {
							dropMCPDenial(denialOpts, denialAudit, "input")
						}
						if !heldNotification {
							sendMCPDenial(denialOpts, denialAudit, BlockedRequest{
								ID:           heldID,
								ErrorCode:    -32007,
								ErrorMessage: "pipelock: receipt emission failed",
							}, blockedCh)
						}
						return
					}
					switch res.FinalDecision {
					case config.ActionAllow:
						if isTrackableRequest(heldLine, heldID) {
							tracker.TrackRequest(heldID, heldAuthorityFrame.Method)
						}
						// forwardMu is held by Prepare's release claim.
						if err := writer.WriteMessage(heldLine); err != nil {
							_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
							return
						}
						commitMCPToolCall(baselineMetricsRecorder(opts, rec), heldBaselineIdentity)
					default:
						if finishDeniedRelease != nil {
							finishDeniedRelease()
						}
						if res.ResolutionSource == deferred.SourceKillSwitch {
							denialAudit = mcpInputGateBlockAudit(scanner.AuditKillSwitch, mcpKillSwitchReason, audit.BlockClassProtective)
							_, _ = fmt.Fprintf(logW, "pipelock: deferred call %s cancelled by kill switch\n", res.DeferID)
						}
						if heldNotification {
							dropMCPDenial(denialOpts, denialAudit, "input")
						}
						if !heldNotification {
							if authorityDenied {
								sendMCPDenial(denialOpts, mcpAuthorityDenialAudit(), *authorityBlockedRequest(heldAuthorityFrame), blockedCh)
								return
							}
							if res.ResolutionSource == deferred.SourceKillSwitch {
								sendMCPDenial(denialOpts, denialAudit, BlockedRequest{
									ID:           heldID,
									LogMessage:   fmt.Sprintf("pipelock: deferred call %s kill switch denied", res.DeferID),
									ErrorCode:    -32004,
									ErrorMessage: deferredKillSwitchMessage(opts),
								}, blockedCh)
								return
							}
							sendMCPDenial(denialOpts, denialAudit, BlockedRequest{
								ID:           heldID,
								ErrorCode:    -32002,
								ErrorMessage: "pipelock: deferred action denied",
							}, blockedCh)
						}
					}
				},
			})
			if holdErr != nil {
				errorMessage, emitErr := emitHoldFailureResolution(opts, logW, holdErr, holdFailureResolution{
					DeferID:       actionID,
					ShardIndex:    receiptShard.ShardIndex,
					ShardSelected: receiptShard.ShardSelected,
					Authority: deferred.AuthoritySnapshot{
						SessionID:         receiptSessionID,
						SessionIDOriginal: receiptSessionIDOriginal,
					},
					Policy: manager.Policy(),
					Target: toolCallName,
					Method: verdict.Method,
					Reason: reasonStr,
				})
				logHoldFailureReceiptGap(logW, actionID, emitErr)
				if isNotification {
					dropMCPDenial(opts, mcpDeferHoldDenialAudit(), "input")
				}
				if !isNotification {
					sendMCPDenial(opts, mcpDeferHoldDenialAudit(), BlockedRequest{
						ID:           verdict.ID,
						ErrorCode:    -32002,
						ErrorMessage: errorMessage,
					}, blockedCh)
				}
				effectiveAction = config.ActionBlock
				break
			}
			if held, ok := manager.Held(actionID); ok {
				profileName := policyVerdict.ResolutionPolicy.ResolverProfile
				if profileName != "" {
					profile, found := policyCfg.DeferResolverProfiles[profileName]
					if !found {
						_ = manager.Resolve(actionID, config.ActionBlock, deferred.SourceApproval)
					} else {
						maybeStartDeferApprovalResolver(resolverRuntime, manager, held, profileName, profile, deferToolArgs, opts.IntegrityCfg, logW)
					}
				}
			}
			continue
		case config.ActionAsk:
			// HITL for input scanning is impractical - fall back to block.
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: blocked %s request (%s) [ask not supported for input scanning]\n",
				lineNum, method, reasonStr)
			denialAudit = mcpInputDecisionBlockAudit(verdict, contentBlock || (!verdict.Clean && !policyVerdict.Matched && bindingAction == "" && chainAction == "" && baselineAction == ""), policyVerdict, bindingAction, chainAction, eval.ChainPatternName, baselineAction)
			sendMCPDenial(opts, denialAudit, BlockedRequest{
				ID:             verdict.ID,
				IsNotification: isNotification,
				LogMessage:     fmt.Sprintf("pipelock: input line %d: blocked (ask fallback)", lineNum),
				ErrorCode:      errCode,
				ErrorMessage:   errMsg,
			}, blockedCh)
		default: // warn
			_, _ = fmt.Fprintf(logW, "pipelock: input line %d: warning — %s request contains flagged content (%s)\n",
				lineNum, method, reasonStr)
			// Cross-request exfiltration check even in warn mode.
			inspectionMode, fallbackReason, matchedPattern, ceeBlockKind := "", "", "", ""
			var ceeContributors []json.RawMessage
			ceeOpts := ceeRecordMCPOptions{
				denialAudit:    &denialAudit,
				sessionKey:     ceeStdioKey,
				entropyPayload: line,
				frame:          frame,
				cee:            cee,
				sc:             sc,
				logW:           logW,
				logger:         auditLogger,
				inspectionMode: &inspectionMode,
				fallbackReason: &fallbackReason,
				matchedPattern: &matchedPattern,
				blockKind:      &ceeBlockKind,
				contributors:   &ceeContributors,
			}
			if reason := ceeRecordMCP(ceeOpts); reason != "" {
				// Capture: record CEE verdict (warn-path).
				obs.ObserveCEEVerdict(context.Background(), &capture.CEERecord{
					Subsurface:        "cee_mcp_stdio",
					Transport:         opts.Transport,
					SessionID:         captureSessionID(opts.Transport),
					SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
					ConfigHash:        opts.captureConfigHash(),
					Profile:           opts.captureProfile(),
					ActionClass:       captureActionClass,
					Request:           capture.CaptureRequest{RPCID: captureRPCID(verdict.ID), CEEContributors: ceeContributors},
					RawFindings: []capture.Finding{{
						Kind:   capture.KindCEE,
						Action: config.ActionBlock,
					}},
					EffectiveAction: config.ActionBlock,
					Outcome:         capture.OutcomeBlocked,
					InspectionMode:  inspectionMode,
					FallbackReason:  fallbackReason,
				})
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: CEE blocked", lineNum),
					ErrorCode:      -32005,
					ErrorMessage:   fmt.Sprintf("pipelock: %s", reason),
				}, blockedCh)
				// A method that carries neither a tool call nor required receipt
				// metadata never minted a receipt identity, and the emitter drops
				// a receipt with an empty action ID. Mint one here so a CEE block
				// on any method leaves evidence, exactly as the authorization
				// block below this loop already does.
				if actionID == "" {
					actionID = receipt.NewActionID()
				}
				if receiptTarget == "" {
					receiptTarget = verdict.Method
				}
				receiptLayerOverride = "cross_request"
				receiptPatternOverride = ceeBlockKind
				if matchedPattern != "" {
					receiptPatternOverride = matchedPattern
				}
				receiptSeverityOverride = "critical"
				_ = emitToolReceipt(config.ActionBlock)
				continue
			}
			contractGate, contractErr := evaluateMCPToolGate(frame, effectiveAction, len(reasons) > 0, opts)
			if contractErr != nil {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditContract, mcpContractEvalReason, audit.BlockClassInfrastructureError)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: contract tool-call evaluation failed: %v\n", lineNum, contractErr)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     fmt.Sprintf("pipelock: input line %d: contract tool-call evaluation failed", lineNum),
					ErrorCode:      -32006,
					ErrorMessage:   "pipelock: contract tool-call evaluation failed",
				}, blockedCh)
				_ = emitToolReceipt(config.ActionBlock)
				continue
			}
			if contractGate.Verdict == config.ActionBlock {
				denialAudit = mcpInputGateBlockAudit(scanner.AuditContract, mcpContractDenyAuditReason, audit.BlockClassProtective)
				_, _ = fmt.Fprintf(logW, "pipelock: input line %d: contract blocked %s %q (%s)\n", lineNum, enforcementKind, enforcementTarget, contractGate.Reason)
				sendMCPDenial(opts, denialAudit, mcpContractBlockRequest(verdict.ID, contractGate, "pipelock: request blocked by live-lock contract"), blockedCh)
				_ = emitToolReceipt(config.ActionBlock, contractGate)
				continue
			}
			contractGateForReceipt = &contractGate
			if err := authorizeMCP(stdioInputCtx, authorityRef, authorityCarrierErr, frame, opts); err != nil {
				if actionID == "" {
					actionID = receipt.NewActionID()
				}
				if receiptTarget == "" {
					receiptTarget = verdict.Method
				}
				receiptLayerOverride, receiptPatternOverride, receiptSeverityOverride = authorityReceiptAttribution()
				_ = emitToolReceipt(config.ActionBlock, contractGate)
				sendMCPDenial(opts, mcpAuthorityDenialAudit(), *authorityBlockedRequest(frame), blockedCh)
				continue
			}
			// Inject envelope for warn-mode tool calls before forwarding.
			fwdLine := line
			if verdict.Method == methodToolsCall {
				buildOpts := envelope.BuildOpts{
					ActionID:       actionID,
					Action:         string(receipt.ClassifyMCPTool(toolCallName, verdict.Method)),
					Verdict:        config.ActionWarn,
					SessionTaint:   taintDecision.Risk.Level.String(),
					TaskID:         taintDecision.Task.CurrentTaskID,
					AuthorityKind:  taintDecision.Authority.String(),
					RequiresReauth: taintDecision.RequiresReauth,
				}
				var emitErr error
				fwdLine, emitErr = emitMCPEnvelopeDecision(envelopeEmitter, MCPDecision{
					Envelope:   &buildOpts,
					InboundMsg: line,
				})
				if emitErr != nil {
					denialAudit = mcpInputGateBlockAudit(scanner.AuditMediationEnvelope, mcpEnvelopeReason, audit.BlockClassInfrastructureError)
					sendMCPDenial(opts, denialAudit, BlockedRequest{
						ID:             verdict.ID,
						IsNotification: isRPCNotification(verdict.ID),
						LogMessage:     "mediation envelope injection failed",
						ErrorCode:      -32002,
						ErrorMessage:   "pipelock: mediation envelope injection failed",
					}, blockedCh)
					continue
				}
			}
			if err := emitToolReceipt(effectiveAction, contractGate); err != nil {
				denialAudit = mcpOperationalBlockAudit(scanner.AuditReceiptEmission, "mcp_input", mcpReceiptEmissionReason)
				sendMCPDenial(opts, denialAudit, BlockedRequest{
					ID:             verdict.ID,
					IsNotification: isRPCNotification(verdict.ID),
					LogMessage:     "receipt emission failed",
					ErrorCode:      -32007,
					ErrorMessage:   "pipelock: receipt emission failed",
					ErrorData:      mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
				}, blockedCh)
				continue
			}
			receiptEmitted = true
			// Forward anyway (warn mode).
			if isTrackableRequest(fwdLine, verdict.ID) {
				tracker.TrackRequest(verdict.ID, verdict.Method)
			}
			if err := forwardMessage(fwdLine); err != nil {
				_, _ = fmt.Fprintf(logW, "pipelock: input forward error: %v\n", err)
				return
			}
			commitMCPToolCall(baselineMetricsRecorder(opts, rec), baselineIdentity)
		}

		// Signal recording: record after action is taken.
		// Successful redirects are clean (not a block). Failed redirects escalate.
		switch {
		case entropyOnlyDecision || numberOnlyDecision:
			// Heuristic findings do not affect the adaptive score.
		case effectiveAction == config.ActionBlock || effectiveAction == config.ActionAsk:
			// Input ask falls back to refusal, so it retains block scoring.
			recordAdaptiveFinding(decide.UpgradedWarningSignal(scoringAction, session.SignalBlock), "mcp_input", joinStrings(reasons))
		case effectiveAction == config.ActionRedirect && !redirectSucceeded:
			recordAdaptiveFinding(session.SignalBlock, "mcp_input", joinStrings(reasons))
		case len(reasons) > 0:
			recordAdaptiveFinding(session.SignalWarning, "mcp_input", joinStrings(reasons))
		default:
			if !hadAdaptiveFinding {
				recordCleanSession(rec, adaptiveCfg, true, adaptiveRecoveryContextWithWarnContext(adaptiveRecoveryContext{
					sessionKey: "default",
					reason:     adaptiveRecoveryClean,
					requestID:  canonicalID(verdict.ID),
					logger:     auditLogger,
					metrics:    m,
				}, stdioInputCtx))
			}
		}

		// Action receipt: emit for tools/call decisions only.
		if !receiptEmitted {
			if contractGateForReceipt != nil {
				_ = emitToolReceipt(effectiveAction, *contractGateForReceipt)
			} else {
				_ = emitToolReceipt(effectiveAction)
			}
		}

		// Capture: record DLP/injection input verdict.
		if !verdict.Clean {
			var rawFindings []capture.Finding
			rawFindings = append(rawFindings, dlpMatchesToFindings(verdict.Matches)...)
			rawFindings = append(rawFindings, responseMatchesToFindings(verdict.Inject, effectiveAction)...)
			rawFindings = append(rawFindings, urlFindingsToCapture(verdict.URLFindings)...)
			rawFindings = append(rawFindings, addressFindingsToCapture(verdict.AddressFindings)...)
			obs.ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
				Subsurface:        "dlp_mcp_input",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
				Request:           capture.CaptureRequest{RPCID: captureRPCID(verdict.ID)},
				TransformKind:     capture.TransformJoinedFields,
				RawFindings:       rawFindings,
				EffectiveAction:   effectiveAction,
				Outcome:           captureOutcome(effectiveAction, false),
			})
		}
		// Capture: record tool policy verdict when policy matched.
		if policyVerdict.Matched {
			var policyFindings []capture.Finding
			for _, r := range policyVerdict.Rules {
				policyFindings = append(policyFindings, capture.Finding{
					Kind:       capture.KindToolPolicy,
					PolicyRule: r,
					Action:     policyVerdict.Action,
				})
			}
			obs.ObserveToolPolicyVerdict(context.Background(), &capture.ToolPolicyRecord{
				Subsurface:        "mcp_tool_policy",
				Transport:         opts.Transport,
				SessionID:         captureSessionID(opts.Transport),
				SessionIDOriginal: captureSessionIDOriginal(opts.Transport),
				ConfigHash:        opts.captureConfigHash(),
				Profile:           opts.captureProfile(),
				ActionClass:       captureActionClass,
				Request: capture.CaptureRequest{
					ToolName:     toolCallName,
					ToolArgsJSON: string(frame.Args),
					MCPMethod:    verdict.Method,
					RPCID:        captureRPCID(verdict.ID),
				},
				RawFindings:     policyFindings,
				EffectiveAction: effectiveAction,
				Outcome:         captureOutcome(effectiveAction, false),
			})
		}
	}
}

// unescapeJSONUnicode resolves JSON \uXXXX escape sequences to their UTF-8
// representation on arbitrary text, including malformed JSON. It is the same
// decoder the URL and text DLP views use: a surrogate pair becomes one scalar,
// an unpaired surrogate escape becomes U+FFFD, and a truncated escape or
// non-hex digits stay as written.
func unescapeJSONUnicode(s string) string {
	return normalize.DecodeJSONUnicodeEscapes(s)
}

// isRPCNotification returns true if the JSON-RPC ID represents a notification.
// A notification has no "id" field (nil/empty) or "id": null. The json.RawMessage
// for null is non-nil with len=4, so len(id)==0 alone is insufficient.
func isRPCNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == jsonrpc.Null
}

func isTrackableRequest(msg []byte, id json.RawMessage) bool {
	return isRequest(msg) && !isRPCNotification(id)
}

// joinStrings joins strings with newline separator, matching jsonrpc.ExtractText pattern.
func joinStrings(ss []string) string {
	return strings.Join(ss, "\n")
}

func inputVerdictReasons(verdict InputVerdict) []string {
	reasons := make([]string, 0, len(verdict.Matches)+len(verdict.Inject)+len(verdict.URLFindings)+len(verdict.AddressFindings)+1)
	for _, m := range verdict.Matches {
		reasons = append(reasons, m.PatternName)
	}
	for _, m := range verdict.Inject {
		reasons = append(reasons, m.PatternName)
	}
	for _, f := range verdict.URLFindings {
		reasons = append(reasons, "url:"+f.Scanner+":"+f.Reason)
	}
	for _, f := range verdict.AddressFindings {
		reasons = append(reasons, "address:"+f.Explanation)
	}
	if verdict.Error != "" {
		reasons = append(reasons, verdict.Error)
	}
	if verdict.RedactedDLPOnly {
		reasons = append(reasons, redactedDLPMarker)
	}
	return reasons
}

func joinInputVerdictReasons(verdict InputVerdict) string {
	reasons := inputVerdictReasons(verdict)
	if len(reasons) == 0 {
		return "input scanning"
	}
	return joinStrings(reasons)
}

// jsonRPCErrorCodeForInputError maps scanner parse failures onto JSON-RPC
// protocol error codes.
func jsonRPCErrorCodeForInputError(errText string) int {
	if strings.HasPrefix(errText, "invalid JSON") || strings.Contains(errText, "redact: blocked (body_unparseable): invalid JSON:") {
		return -32700
	}
	return -32600
}

// injectMCPEnvelope injects a mediation envelope into a JSON-RPC message's
// params._meta field. Returns the modified message bytes, or the original
// message unmodified if the message is not an envelope-bearing shape.
// Malformed, null, or non-object params fail closed through a returned error.
// A malformed _meta member is normalized to a fresh object so
// attacker-controlled metadata cannot suppress required mediation.
func injectMCPEnvelope(msg []byte, emitter *envelope.Emitter, buildOpts envelope.BuildOpts) ([]byte, error) {
	if emitter == nil {
		return msg, nil
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return msg, nil
	}

	paramsRaw, ok := rpc["params"]
	if !ok {
		return msg, nil
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return msg, fmt.Errorf("parse MCP params for mediation envelope: %w", err)
	}
	// json.Unmarshal of JSON null into a map succeeds with a nil map, so
	// params:null reaches here without an error. Fail closed rather than
	// normalizing it to an object: a tools/call never legitimately carries
	// null params, and silently rewriting it would diverge from the
	// non-object fail-closed path above.
	if params == nil {
		return msg, fmt.Errorf("parse MCP params for mediation envelope: params must be a JSON object")
	}

	// Use json.RawMessage to preserve existing _meta members byte-for-byte.
	// map[string]any would round-trip through encoding/json and lose precision
	// on large integer values from other extensions.
	meta := make(map[string]json.RawMessage)
	if metaRaw, exists := params["_meta"]; exists {
		if err := json.Unmarshal(metaRaw, &meta); err != nil {
			meta = make(map[string]json.RawMessage)
		}
	}
	if meta == nil {
		meta = make(map[string]json.RawMessage)
	}

	// Strip any existing mediation key, then inject.
	delete(meta, envelope.MCPMetaKey)
	env, err := emitter.Build(buildOpts)
	if err != nil {
		out := marshalMCPWithMeta(msg, rpc, params, meta)
		return out, fmt.Errorf("inject MCP mediation envelope: %w", err)
	}
	envData := env.ToMCPMeta()
	envBytes, err := marshalMCPMessage(envData)
	if err != nil {
		out := marshalMCPWithMeta(msg, rpc, params, meta)
		return out, fmt.Errorf("marshal MCP mediation envelope: %w", err)
	}
	meta[envelope.MCPMetaKey] = envBytes

	out := marshalMCPWithMeta(msg, rpc, params, meta)
	if bytes.Equal(out, msg) {
		return out, fmt.Errorf("marshal MCP message with mediation envelope")
	}
	return out, nil
}

func marshalMCPWithMeta(original []byte, rpc, params map[string]json.RawMessage, meta map[string]json.RawMessage) []byte {
	// Re-serialize without HTML escaping so tool-call payloads containing
	// <, >, or & keep those literal bytes. This matches marshalMCPMessage
	// used on the redaction forward path; plain json.Marshal HTML-escapes
	// those bytes (to their \u-prefixed escapes), which would mutate the
	// request on the wire.
	metaBytes, err := marshalMCPMessage(meta)
	if err != nil {
		return original
	}
	params["_meta"] = metaBytes

	paramsBytes, err := marshalMCPMessage(params)
	if err != nil {
		return original
	}
	rpc["params"] = paramsBytes

	out, err := marshalMCPMessage(rpc)
	if err != nil {
		return original
	}
	return out
}

// stripInboundMCPMeta removes the com.pipelock/mediation key from a
// JSON-RPC message's params._meta before scanning. Prevents spoofed
// mediation metadata from passing through unmodified.
// Returns the modified message or the original if parsing fails.
func stripInboundMCPMeta(msg []byte) []byte {
	out, _, _ := extractInboundMCPAuthority(msg)
	return out
}

// extractInboundMCPAuthority consumes both Pipelock-owned _meta members while
// preserving every unrelated extension member. Duplicate keys are returned as
// an error before encoding/json can collapse them.
func extractInboundMCPAuthority(msg []byte) ([]byte, string, error) {
	trimmed := bytes.TrimSpace(msg)
	if err := jsonrpc.ValidateMessageKeys(trimmed); err != nil {
		// Preserve invalid bytes until the input gate rejects them; decoding
		// and remarshal could repair malformed text or collapse duplicate keys.
		return msg, "", err
	}

	var rpc map[string]json.RawMessage
	if err := json.Unmarshal(msg, &rpc); err != nil {
		return msg, "", err
	}

	paramsRaw, ok := rpc["params"]
	if !ok {
		return msg, "", authority.ErrMissingReference
	}

	var params map[string]json.RawMessage
	if err := json.Unmarshal(paramsRaw, &params); err != nil {
		return msg, "", err
	}
	if params == nil {
		return msg, "", authority.ErrMissingReference
	}

	metaRaw, ok := params["_meta"]
	if !ok {
		return msg, "", authority.ErrMissingReference
	}

	var meta map[string]json.RawMessage
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		return msg, "", err
	}

	if meta == nil {
		return msg, "", authority.ErrMissingReference
	}
	_, hasMediation := meta[envelope.MCPMetaKey]
	authorityRaw, hasAuthority := meta[authority.MCPMetaKey]
	if !hasMediation && !hasAuthority {
		return msg, "", authority.ErrMissingReference
	}

	delete(meta, envelope.MCPMetaKey)
	delete(meta, authority.MCPMetaKey)

	metaBytes, err := marshalMCPMessage(meta)
	if err != nil {
		return msg, "", err
	}
	params["_meta"] = metaBytes

	paramsBytes, err := marshalMCPMessage(params)
	if err != nil {
		return msg, "", err
	}
	rpc["params"] = paramsBytes

	out, err := marshalMCPMessage(rpc)
	if err != nil {
		return msg, "", err
	}
	if !hasAuthority {
		return out, "", authority.ErrMissingReference
	}
	var ref string
	if err := json.Unmarshal(authorityRaw, &ref); err != nil {
		return out, "", authority.ErrMalformedReference
	}
	if strings.TrimSpace(ref) == "" || len(ref) > authority.MaxReferenceBytes {
		return out, "", authority.ErrMalformedReference
	}
	return out, ref, nil
}
