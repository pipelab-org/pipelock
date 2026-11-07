// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/mcp/tools"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	session "github.com/luckyPipewrench/pipelock/internal/session"
)

func (o MCPProxyOpts) snapshotWatchPolicy() MCPProxyOpts {
	if o.ReloadMu != nil {
		o.ReloadMu.RLock()
		defer o.ReloadMu.RUnlock()
	}
	o.WatchOnly = o.watchOnly()
	o.WatchOnlyFn = nil
	o.Scanner = o.scanner()
	o.ScannerFn = nil
	o.PolicyHash = o.receiptPolicyHash()
	o.PolicyHashFn = nil
	o.ConfigHash = o.captureConfigHash()
	o.ConfigHashFn = nil
	o.ReloadMu = nil
	return o
}

func (o MCPProxyOpts) watchOnly() bool {
	if o.WatchOnlyFn != nil {
		return o.WatchOnlyFn()
	}
	return o.WatchOnly
}

func (o MCPProxyOpts) recordWatch(name, reason, action string, n int64, enforced bool) {
	surface := o.Transport
	if surface == "" {
		surface = transportMCPStdio
	}
	if o.AuditLogger != nil {
		o.AuditLogger.LogWatchOnly(surface, name, reason, action, n, enforced)
	}
	if o.Metrics != nil {
		o.Metrics.RecordWatchOnly(surface, name, action, n)
	}
}

// observeInputGate joins the shared evaluator's existing early-return sites.
// Observation continues through later gates so an earlier policy finding cannot
// hide a credential-floor finding or another independent would-block decision.
func (o MCPProxyOpts) observeInputGate(eval *MCPInputEvaluation, n int) bool {
	if !o.watchOnly() {
		return false
	}
	if eval.BlockingGate != "" {
		action := config.ActionBlock
		count := int64(0)
		if eval.BlockingGate == blockingGateParseError {
			action, count = "uninspected", int64(n)
		}
		o.recordWatch(eval.BlockingGate, eval.BlockingGate, action, count, false)
		eval.BlockingGate = ""
	}
	return true
}

func watchCoreMatches(matches []scanner.TextDLPMatch) bool {
	for _, match := range matches {
		if !match.Warn && scanner.IsCoreCriticalMatch(match) {
			return true
		}
	}
	return false
}

func watchCoreInput(v InputVerdict) bool {
	if watchCoreMatches(v.Matches) {
		return true
	}
	for _, finding := range v.URLFindings {
		if scanner.IsCoreCredentialResult(finding) {
			return true
		}
	}
	return false
}

// watchInputDecision uses the existing gate evaluator on the original message.
// Changes such as redaction, redirects and envelope injection are observed but
// never applied to the message that this decision returns.
func watchInputDecision(msg []byte, logW io.Writer, sessionKey string, opts MCPProxyOpts) httpInputDecision {
	opts.WatchOnly, opts.WatchOnlyFn = true, nil
	result := httpInputDecision{ForwardMessage: msg}
	frame := ParseMCPFrame(msg)
	if err := opts.checkServerIdentity(); err != nil {
		opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "server identity no longer authorized"}
		return result
	}
	stripped, authorityRef, authorityErr := extractInboundMCPAuthority(msg)
	if err := authorizeMCP(opts.warnContext(), authorityRef, authorityErr, frame, opts); err != nil {
		opts.recordWatch("authority", "external action grant refused", config.ActionBlock, 0, true)
		result.Blocked = authorityBlockedRequest(frame)
		return result
	}
	if !bytes.Equal(stripped, msg) {
		opts.recordWatch("authority", "proxy-owned metadata consumed", config.ActionStrip, 0, true)
		result.ForwardMessage = stripped
	}
	if opts.KillSwitch != nil {
		if d := opts.KillSwitch.IsActiveMCP(msg); d.Active {
			opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
			result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorCode: -32004, ErrorMessage: d.Message}
			return result
		}
	}
	action, parseAction, enabled := config.ActionBlock, config.ActionBlock, false
	if cfg := opts.inputCfg(); cfg != nil {
		action, parseAction, enabled = cfg.Action, cfg.OnParseError, cfg.Enabled
	}
	eval := EvaluateMCPInputGates(opts.warnContext(), frame, msg, sessionKey, opts, action, parseAction, enabled)
	// Always scan the original content for the immutable floor, including when
	// inspection of its JSON shape was incomplete or configurable scanning is off.
	floor := opts.scanner().ScanTextForDLP(opts.warnContext(), string(msg))
	core := watchCoreInput(eval.ContentVerdict) || watchCoreMatches(floor.Matches) || watchCoreMatches(eval.A2AResult.DLPFindings)
	if core {
		opts.recordWatch("dlp", "core credential floor", config.ActionBlock, 0, true)
		result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "pipelock: core credential floor enforced in watch-only"}
		return result
	}
	if eval.ContentVerdict.Error != "" {
		opts.recordWatch("mcp_input", eval.ContentVerdict.Error, "uninspected", int64(len(msg)), false)
	} else if !eval.ContentVerdict.Clean {
		opts.recordWatch("mcp_input", joinInputVerdictReasons(eval.ContentVerdict), inputVerdictEffectiveAction(eval.ContentVerdict, action), 0, false)
	}
	if eval.PolicyVerdict.Matched {
		opts.recordWatch("tool_policy", strings.Join(eval.PolicyVerdict.Rules, ","), eval.PolicyVerdict.Action, 0, false)
	}
	if eval.BindingAction != "" {
		opts.recordWatch("session_binding", eval.BindingReason, eval.BindingAction, 0, false)
	}
	if eval.ChainMatched {
		opts.recordWatch("chain", eval.ChainReason, eval.ChainAction, 0, false)
	}
	if frame.IsBatch || frame.KeyValidationErr != nil {
		opts.recordWatch("mcp_protocol", "message shape refused by enforced mode", config.ActionBlock, 0, false)
	}
	if opts.Rec != nil {
		if upgraded := decide.UpgradeAction("", opts.Rec.EscalationLevel(), opts.adaptiveCfg()); upgraded != "" {
			opts.recordWatch("adaptive", "session action upgrade", "escalate", 0, false)
		}
	}
	redacted, _, err := applyMCPToolCallRedactionWithConfig(msg, opts.redactionConfig())
	if err != nil {
		opts.recordWatch("redaction", err.Error(), "uninspected", int64(len(msg)), false)
	} else if !bytes.Equal(msg, redacted) {
		opts.recordWatch("redaction", "request redaction", config.ActionStrip, 0, false)
	}
	if opts.ToolFreezer != nil && opts.FrozenToolStableKey != "" && frame.IsToolsCall() && opts.ToolFreezer.IsFrozen(opts.FrozenToolStableKey) && !opts.ToolFreezer.IsToolAllowed(opts.FrozenToolStableKey, frame.ToolCallName) {
		opts.recordWatch("frozen_tool", "tool outside frozen inventory", config.ActionBlock, 0, false)
	}
	if eval.CrossAgentEscalate {
		opts.recordWatch("adaptive", "cross-agent escalation", "escalate", 0, false)
	}
	if gate, err := evaluateMCPToolGate(frame, config.ActionAllow, false, opts); err != nil {
		opts.recordWatch("contract", "contract evaluation unavailable", "uninspected", int64(len(msg)), false)
	} else if gate.Verdict != config.ActionAllow {
		opts.recordWatch("contract", gate.Reason, gate.Verdict, 0, false)
	}
	pattern, kind := "", ""
	if reason := ceeRecordMCP(ceeRecordMCPOptions{
		sessionKey: sessionKey, entropyPayload: msg, frame: frame, cee: opts.cee(), sc: opts.scanner(), logW: logW,
		matchedPattern: &pattern, blockKind: &kind, watchOnly: true, onWatch: opts.recordWatch,
	}); reason != "" {
		if config.IsCoreDLPPatternName(pattern) {
			opts.recordWatch("cross_request", "core credential floor", config.ActionBlock, 0, true)
			result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "pipelock: core credential floor enforced in watch-only"}
			return result
		}
		opts.recordWatch("cross_request", reason, "uninspected", int64(len(msg)), false)
	}
	if cfg := opts.adaptiveCfg(); cfg != nil && cfg.Enabled {
		if !eval.ContentVerdict.Clean || eval.PolicyVerdict.Matched || eval.BindingAction != "" || eval.ChainMatched {
			observeWatchMCPSignal(opts, opts.Rec, watchSignalForAction(config.StricterAction(action, config.StricterAction(eval.PolicyVerdict.Action, config.StricterAction(eval.BindingAction, eval.ChainAction)))), decide.EscalationParams{Threshold: cfg.EscalationThreshold, DenialScanner: "mcp_input", DenialReason: "observed input refusal", PolicyHash: opts.receiptPolicyHash()})
		} else {
			observeWatchMCPClean(opts)
		}
	}
	if scanner.HasInspectionLimit(eval.ContentVerdict.Matches) {
		opts.recordWatch("mcp_input", "text inspection limit", "uninspected", int64(len(msg)), false)
	}
	for _, finding := range eval.ContentVerdict.URLFindings {
		if scanner.IsURLInspectionLimitResult(finding) {
			opts.recordWatch("mcp_input", "URL inspection limit", "uninspected", int64(len(msg)), false)
			break
		}
	}
	findings := dlpMatchesToFindings(eval.ContentVerdict.Matches)
	findings = append(findings, responseMatchesToFindings(eval.ContentVerdict.Inject, action)...)
	findings = append(findings, urlFindingsToCapture(eval.ContentVerdict.URLFindings)...)
	opts.captureObserver().ObserveDLPVerdict(context.Background(), &capture.DLPVerdictRecord{
		Subsurface: "dlp_mcp_input", Transport: opts.Transport, SessionID: captureSessionID(opts.Transport),
		SessionIDOriginal: captureSessionIDOriginal(opts.Transport), ConfigHash: opts.captureConfigHash(),
		Profile: opts.captureProfile(), Request: capture.CaptureRequest{RPCID: captureRPCID(frame.ID)},
		TransformKind: capture.TransformJoinedFields, RawFindings: findings,
		EffectiveAction: config.ActionWarn, Outcome: capture.OutcomeWarned, SkipReason: "watch_only",
	})
	emitWatchReceipt(opts, logW, frame, len(msg))
	return result
}

func emitWatchReceipt(opts MCPProxyOpts, logW io.Writer, frame MCPFrame, n int) {
	decision := MCPDecision{Receipt: receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: config.ActionWarn, Layer: "watch_only", Pattern: "watch-only forwarded original message", Transport: opts.Transport, Target: "mcp://message", MCPMethod: frame.Method, RequestID: canonicalID(frame.ID)}}
	// Required receipt failures are observed in this mode. They never turn the
	// successful forwarding decision into a signed blocked decision.
	required := opts.requireReceipts()
	opts.RequireReceipts, opts.RequireReceiptsFn = false, nil
	if _, err := opts.emitReceiptDecision(decision); err != nil {
		opts.recordWatch("receipt", "receipt emission failed", "uninspected", int64(n), false)
		if logW != nil {
			_, _ = fmt.Fprintln(logW, "pipelock: watch-only receipt emission failed")
		}
	} else if required && opts.receiptEmitter() == nil && opts.ReceiptGroup == nil {
		opts.recordWatch("receipt", "required receipt unavailable", "uninspected", int64(n), false)
	}
}

func forwardWatchResponse(line []byte, writer transport.MessageWriter, logW io.Writer, tracker *RequestTracker, opts MCPProxyOpts) (bool, error) {
	opts.WatchOnly, opts.WatchOnlyFn = true, nil
	frame := ParseMCPFrame(line)
	if err := opts.checkServerIdentity(); err != nil {
		opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		return true, err
	}
	if opts.KillSwitch != nil {
		if d := opts.KillSwitch.IsActiveMCP(line); d.Active {
			opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
			if frame.ID == nil {
				return true, nil
			}
			return true, writer.WriteMessage(blockSessionDenyResponse(frame.ID, "kill switch enforced in watch-only"))
		}
	}
	trackedMethod := ""
	if tracker != nil && isResponse(line) {
		if tracked, ok := tracker.Consume(frame.ID); ok {
			trackedMethod = tracked.Method
		} else if tracker.Seeded() {
			opts.recordWatch("mcp_correlation", "unsolicited response", config.ActionBlock, 0, false)
		}
	}
	sc := opts.scanner()
	respOpts := opts.responseScanOptions()
	a2aOpts := opts.a2aResponseOpts(respOpts)
	a2aOpts.Method = trackedMethod
	verdict := ScanResponseA2A(line, sc, a2aOpts)
	// Ordinary inbound MCP credentials follow response policy. Only the
	// existing field-aware A2A route has an immutable credential floor.
	isA2A := a2aOpts != nil && a2aOpts.Cfg != nil && a2aOpts.Cfg.Enabled && (IsA2AMethod(trackedMethod) || isAgentCardResultShape(line))
	core := isA2A && watchCoreMatches(verdict.DLPMatches)
	if core {
		opts.recordWatch("dlp", "core credential floor", config.ActionBlock, 0, true)
		if frame.ID == nil {
			return true, nil
		}
		return true, writer.WriteMessage(blockResponseReason(frame.ID, "core credential floor enforced in watch-only"))
	}
	found := !verdict.Clean
	observedAction := verdict.Action
	if observedAction == "" {
		observedAction = sc.ResponseAction()
	}
	taintKinds := ResponseTaintFindingKinds(verdict)
	if verdict.Error != "" {
		opts.recordWatch("mcp_response", verdict.Error, "uninspected", int64(len(line)), false)
	} else if !verdict.Clean {
		opts.recordWatch("mcp_response", "response scanner finding", observedAction, 0, false)
	}
	if cfg := opts.toolCfg(); cfg != nil {
		toolResult := tools.ScanToolsForMethodContext(opts.warnContext(), line, sc, cfg.WithServerMode(opts.ServerName, opts.ServerBinding, opts.ServerBindingMode, opts.ServerRevision), trackedMethod)
		taintKinds = session.MergeFindingKinds(taintKinds, toolTaintFindingKinds(toolResult, !toolResult.Clean, false))
		if toolResult.IsToolsList && !toolResult.Clean {
			observedAction = config.StricterAction(observedAction, cfg.Action)
			found = true
			if toolResult.ResourceLimit != "" {
				opts.recordWatch("mcp_tools", toolResult.ResourceLimit, "uninspected", int64(len(line)), false)
			} else {
				opts.recordWatch("mcp_tools", "tool definition finding", cfg.Action, 0, false)
			}
		}
		if toolResult.IsToolsList && cfg.Baseline != nil {
			reservation, err := cfg.Baseline.ReserveToolInventory(toolResult.ToolNames, toolResult.ToolDefs)
			if err != nil {
				opts.recordWatch("mcp_tools", "inventory unavailable", "uninspected", int64(len(line)), false)
			} else {
				defer reservation.Release()
				_ = reservation.Commit(toolResult.Clean)
			}
		}
	}
	if cfg := opts.provenanceCfg(); cfg != nil && cfg.Enabled && isToolsListResponse(line) {
		pv := VerifyToolsListProvenance(line, cfg)
		if pv.Block {
			opts.recordWatch("provenance", pv.Error, pv.Action, 0, false)
			found = true
		}
	}
	mediaResult := applyMCPResponseMediaPolicy(line, opts.mediaPolicy(), opts.Transport)
	if mediaResult.Blocked {
		opts.recordWatch("media", mediaResult.BlockReason, config.ActionBlock, 0, false)
		found = true
	} else if mediaResult.Changed {
		opts.recordWatch("media", "response media rewrite", config.ActionStrip, 0, false)
		found = true
	}
	if frame.IsBatch || frame.KeyValidationErr != nil {
		opts.recordWatch("mcp_protocol", "response shape refused by enforced mode", config.ActionBlock, 0, false)
	}
	opts.captureObserver().ObserveResponseVerdict(context.Background(), &capture.ResponseVerdictRecord{
		Subsurface: "response_mcp", Transport: opts.Transport, SessionID: captureSessionID(opts.Transport),
		SessionIDOriginal: captureSessionIDOriginal(opts.Transport), ConfigHash: opts.captureConfigHash(),
		Profile: opts.captureProfile(), Request: capture.CaptureRequest{RPCID: captureRPCID(frame.ID)},
		TransformKind: capture.TransformJoinedFields, WirePayload: line, RawFindings: append(dlpMatchesToFindings(verdict.DLPMatches), responseMatchesToFindings(verdict.Matches, observedAction)...),
		EffectiveAction: config.ActionWarn, Outcome: capture.OutcomeWarned, SkipReason: "watch_only",
	})
	if cfg := opts.adaptiveCfg(); cfg != nil && cfg.Enabled {
		if found {
			observeWatchMCPSignal(opts, opts.Rec, watchSignalForAction(observedAction), decide.EscalationParams{Threshold: cfg.EscalationThreshold, DenialScanner: "mcp_response", DenialReason: "observed response refusal", PolicyHash: opts.receiptPolicyHash()})
		} else {
			observeWatchMCPClean(opts)
		}
	}
	if len(verdict.Unscanned) > 0 {
		opts.recordWatch("mcp_response", "response fields uninspected", "uninspected", int64(len(line)), false)
	}
	observeMCPResponseFindings(opts, taintKinds)
	emitWatchReceipt(opts, logW, frame, len(line))
	if err := writer.WriteMessage(line); err != nil {
		return found, fmt.Errorf("forwarding watch-only MCP response: %w", err)
	}
	return found, nil
}

func watchCoreFragments(matches []scanner.DLPMatch) bool {
	for _, match := range matches {
		if config.IsCoreDLPPatternName(match.PatternName) {
			return true
		}
	}
	return false
}

// Match the existing ForwardScanned signal mapping for block, strip and warn.
func watchSignalForAction(action string) session.SignalType {
	switch action {
	case config.ActionBlock:
		return session.SignalBlock
	case config.ActionStrip:
		return session.SignalStrip
	default:
		return session.SignalWarning
	}
}
