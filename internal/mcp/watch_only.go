// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/capture"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/decide"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
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
	o.RequireReceipts = o.requireReceipts()
	o.RequireReceiptsFn = nil
	o.Scanner = o.scanner()
	o.ScannerFn = nil
	o.PolicyHash = o.receiptPolicyHash()
	o.PolicyHashFn = nil
	o.ConfigHash = o.captureConfigHash()
	o.ConfigHashFn = nil
	o.InputCfg, o.InputCfgFn = o.inputCfg(), nil
	o.RequestBodyCfg, o.RequestBodyFn = o.requestBodyCfg(), nil
	o.ToolCfg, o.ToolCfgFn = o.toolCfg(), nil
	o.PolicyCfg, o.PolicyCfgFn = o.policyCfg(), nil
	o.ChainMatcher, o.ChainMatcherFn = o.chainMatcher(), nil
	o.AdaptiveCfg, o.AdaptiveCfgFn = o.adaptiveCfg(), nil
	o.AirlockCfg, o.AirlockCfgFn = o.airlockCfg(), nil
	o.TaintCfg, o.TaintCfgFn = o.taintCfg(), nil
	o.ProvenanceCfg, o.ProvenanceCfgFn = o.provenanceCfg(), nil
	o.A2ACfg, o.A2ACfgFn = o.a2aCfg(), nil
	o.MediaPolicy, o.MediaPolicyFn = o.mediaPolicy(), nil
	redaction := o.redactionConfig()
	o.RedactionCfgFn = func() MCPRedactionConfig { return redaction }
	if o.WatchOnlyGenerationFn != nil && o.ReloadMu != nil {
		o.watchGeneration = o.WatchOnlyGenerationFn()
		o.watchReloadMu = o.ReloadMu
	}
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
		if !match.Warn && (scanner.IsCoreCriticalMatch(match) || scanner.IsHostnameExfilMatch(match) || match.IsInspectionLimit() || match.PatternName == uninspectableSplitSecretFieldsReason) {
			return true
		}
	}
	return false
}

func watchCoreInput(v InputVerdict) bool {
	if v.Error != "" || watchCoreMatches(v.Matches) {
		return true
	}
	for _, finding := range v.URLFindings {
		if scanner.IsCoreCriticalResult(finding) || scanner.IsHostnameExfilResult(finding) {
			return true
		}
	}
	return false
}

// watchInputDecision uses the existing gate evaluator on the original message.
// Changes such as redaction, redirects and envelope injection are observed but
// never applied to the message that this decision returns.
func watchInputDecision(msg []byte, logW io.Writer, sessionKey string, opts MCPProxyOpts) (result httpInputDecision) {
	opts.WatchOnly, opts.WatchOnlyFn = true, nil
	result = httpInputDecision{ForwardMessage: msg}
	frame := ParseMCPFrame(msg)
	denialAudit := mcpInputBlockAudit(InputVerdict{})
	defer func() {
		result.Blocked = inputMCPDenial(opts, denialAudit, result.Blocked)
	}()
	receiptHandled := false
	receiptLayer, receiptPattern := "watch_only", "forwarded original message"
	defer func() {
		if receiptHandled {
			return
		}
		verdict := config.ActionWarn
		if result.Blocked != nil {
			verdict = config.ActionBlock
			if receiptPattern == "forwarded original message" {
				receiptPattern = result.Blocked.ErrorMessage
			}
		}
		if err := emitWatchReceipt(opts, logW, frame, verdict, receiptLayer, receiptPattern); err != nil && opts.requireReceipts() && result.Blocked == nil {
			denialAudit = mcpReceiptMcpInputDenialAudit()
			opts.recordWatch("receipt", "required receipt unavailable", config.ActionBlock, 0, true)
			result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorCode: -32007, ErrorMessage: requiredReceiptFailureMessage(err), ErrorData: mcpBlockReasonData(blockreason.ReceiptEmissionFailed)}
		}
	}()
	if opts.scanner() == nil {
		denialAudit = mcpOperationalBlockAudit(scanner.AuditScannerUnavailable, "mcp_input", "MCP scanner unavailable")
		receiptLayer = "scanner_unavailable"
		opts.recordWatch(receiptLayer, "scanner unavailable", config.ActionBlock, 0, true)
		result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "scanner unavailable, enforced in watch-only"}
		return result
	}
	if err := opts.checkServerIdentity(); err != nil {
		denialAudit = mcpInputGateBlockAudit(scanner.AuditAgentIdentity, "MCP server identity is no longer authorized", audit.BlockClassProtective)
		receiptLayer = "identity"
		opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "server identity no longer authorized"}
		return result
	}
	stripped, authorityRef, authorityErr := extractInboundMCPAuthority(msg)
	if err := authorizeMCP(opts.warnContext(), authorityRef, authorityErr, frame, opts); err != nil {
		denialAudit = mcpAuthorityDenialAudit()
		receiptLayer = "authority"
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
			if manager := opts.deferManager(); manager != nil {
				manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
			}
			denialAudit = mcpKillMcpInputDenialAudit()
			batch := refuseKillSwitchRequest(opts, logW, frame, d)
			receiptHandled = true
			result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorCode: -32004, ErrorMessage: d.Message, SyntheticResponse: batch}
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
	core := floor.Err() != nil || watchCoreInput(eval.ContentVerdict) || watchCoreMatches(floor.Matches) || watchCoreMatches(eval.A2AResult.DLPFindings) || eval.A2AResult.InspectionIncomplete || eval.A2AResult.ScanError != ""
	for _, finding := range eval.A2AResult.URLFindings {
		core = core || scanner.IsCoreCriticalResult(finding) || scanner.IsHostnameExfilResult(finding)
	}
	if frame.IsBatch || frame.KeyValidationErr != nil || frameParseErrFailsClosed(frame.ParseErr) {
		core = true
	}
	receiptLayer, receiptPattern, _ = pickAttribution(eval)
	observed := append(inputVerdictReasons(eval.ContentVerdict), eval.DoWReason, eval.BindingReason, eval.ChainReason)
	observed = append(observed, eval.PolicyVerdict.Rules...)
	for _, reason := range observed {
		if reason != "" {
			receiptPattern += "; would-block: " + reason
		}
	}
	if receiptPattern == "" {
		receiptPattern = "forwarded original message"
	}
	if core {
		denialAudit = mcpInputBlockAudit(eval.ContentVerdict)
		receiptLayer = mcpReceiptLayerInput
		receiptPattern = joinInputVerdictReasons(eval.ContentVerdict)
		if receiptPattern == "" {
			receiptPattern = "audit-mode security floor"
		}
		opts.recordWatch("dlp", "audit-mode security floor", config.ActionBlock, 0, true)
		result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "pipelock: audit-mode security floor enforced in watch-only"}
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
		if config.IsCoreDLPPatternName(pattern) || (scanner.TextDLPMatch{PatternName: pattern}).IsInspectionLimit() || kind == ceeBlockKindSessionCapacity || kind == ceeBlockKindOwnerMismatch {
			opts.recordWatch("cross_request", "core credential floor", config.ActionBlock, 0, true)
			result.Blocked = &BlockedRequest{ID: frame.ID, IsNotification: isRPCNotification(frame.ID), ErrorMessage: "pipelock: core credential floor enforced in watch-only"}
			return result
		}
		opts.recordWatch("cross_request", reason, "uninspected", int64(len(msg)), false)
	}
	if cfg := opts.adaptiveCfg(); cfg != nil && cfg.Enabled {
		if !eval.ContentVerdict.Clean || eval.PolicyVerdict.Matched || eval.BindingAction != "" || eval.ChainMatched || (!eval.DoWAllowed && eval.DoWAction != "") {
			observedAction := config.StricterAction(eval.PolicyVerdict.Action, config.StricterAction(eval.BindingAction, eval.ChainAction))
			if !eval.ContentVerdict.Clean {
				observedAction = config.StricterAction(observedAction, inputVerdictEffectiveAction(eval.ContentVerdict, action))
			}
			reason := "observed input refusal"
			if !eval.DoWAllowed && eval.DoWAction != "" {
				observedAction = config.StricterAction(observedAction, eval.DoWAction)
				reason = eval.DoWReason
			}
			observeWatchMCPSignal(opts, opts.Rec, watchSignalForAction(observedAction), decide.EscalationParams{Threshold: cfg.EscalationThreshold, DenialScanner: "mcp_input", DenialReason: reason, PolicyHash: opts.receiptPolicyHash()})
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
	return result
}

func emitWatchReceipt(opts MCPProxyOpts, logW io.Writer, frame MCPFrame, verdict, layer, pattern string) error {
	target := frame.ToolCallName
	if target == "" {
		target = frame.Method
	}
	if target == "" {
		target = "mcp://message"
	}
	surface := opts.Transport
	if surface == "" {
		surface = transportMCPStdio
	}
	decision := MCPDecision{Receipt: receipt.EmitOpts{ActionID: receipt.NewActionID(), Verdict: verdict, Layer: layer, Pattern: pattern, Transport: surface, Target: target, MCPMethod: frame.Method, ToolName: frame.ToolCallName, RequestID: canonicalID(frame.ID)}, RequireReceipt: opts.requireReceipts(), RequiredMode: opts.requireReceipts()}
	_, err := opts.emitReceiptDecision(decision)
	if err != nil {
		opts.recordWatch("receipt", "receipt emission failed", config.ActionBlock, 0, opts.requireReceipts())
		if logW != nil {
			_, _ = fmt.Fprintln(logW, "pipelock: watch-only receipt emission failed")
		}
	}
	return err
}

func forwardWatchResponse(line []byte, writer transport.MessageWriter, logW io.Writer, tracker *RequestTracker, opts MCPProxyOpts) (bool, error) {
	opts.WatchOnly, opts.WatchOnlyFn = true, nil
	frame := ParseMCPFrame(line)
	if frame.IsBatch || frame.KeyValidationErr != nil {
		opts.recordWatch("mcp_protocol", "invalid response shape", config.ActionBlock, 0, true)
		return true, fmt.Errorf("invalid response shape, enforced in watch-only")
	}
	if opts.scanner() == nil {
		opts.recordWatch("scanner_unavailable", "scanner unavailable", config.ActionBlock, 0, true)
		_ = emitWatchReceipt(opts, logW, frame, config.ActionBlock, "scanner_unavailable", "scanner unavailable")
		dropMCPDenial(opts, mcpOperationalBlockAudit(scanner.AuditScannerUnavailable, "mcp_response", "MCP scanner unavailable"), "response")
		return true, fmt.Errorf("scanner unavailable, enforced in watch-only")
	}
	if err := opts.checkServerIdentity(); err != nil {
		opts.recordWatch("identity", "server identity no longer authorized", config.ActionBlock, 0, true)
		_ = emitWatchReceipt(opts, logW, frame, config.ActionBlock, "identity", "server identity no longer authorized")
		dropMCPDenial(opts, mcpIdentityMcpResponseDenialAudit(), "response")
		return true, err
	}
	if opts.KillSwitch != nil {
		if d := opts.KillSwitch.IsActiveMCP(line); d.Active {
			opts.recordWatch("kill_switch", "operator kill switch", config.ActionBlock, 0, true)
			if manager := opts.deferManager(); manager != nil {
				manager.ResolveAll(config.ActionBlock, deferred.SourceKillSwitch)
			}
			_ = emitWatchReceipt(opts, logW, frame, config.ActionBlock, "kill_switch", "operator kill switch")
			if frame.ID == nil {
				dropMCPDenial(opts, mcpKillMcpResponseDenialAudit(), "response")
				return true, nil
			}
			return true, writeMCPDenial(opts, mcpKillMcpResponseDenialAudit(), writer, blockSessionDenyResponse(frame.ID, "kill switch enforced in watch-only"))
		}
	}
	var findings []string
	observe := func(layer, reason, action string, n int64, enforced bool) {
		opts.recordWatch(layer, reason, action, n, enforced)
		findings = append(findings, layer+": "+reason+" ("+action+")")
	}
	trackedMethod := ""
	if tracker != nil && isResponse(line) {
		if tracked, ok := tracker.Consume(frame.ID); ok {
			trackedMethod = tracked.Method
		} else if tracker.Seeded() {
			observe("mcp_correlation", "unsolicited response", config.ActionBlock, 0, true)
			return true, fmt.Errorf("unsolicited response, enforced in watch-only")
		}
	}
	sc := opts.scanner()
	respOpts := opts.responseScanOptions()
	a2aOpts := opts.a2aResponseOpts(respOpts)
	a2aOpts.Method = trackedMethod
	verdict := ScanResponseA2A(line, sc, a2aOpts)
	if toolCfg := opts.toolCfg(); toolCfg != nil && !toolCfg.HeaderContractsOnly && isToolsListResponse(line) {
		verdict = ScanResponseDispatch(line, sc, true, respOpts)
	}
	// Ordinary inbound MCP credentials follow response policy. Only the
	// existing field-aware A2A route has an immutable credential floor.
	isA2A := a2aOpts != nil && a2aOpts.Cfg != nil && a2aOpts.Cfg.Enabled && (IsA2AMethod(trackedMethod) || isAgentCardResultShape(line))
	core := isA2A && watchCoreMatches(verdict.DLPMatches)
	if core {
		observe("dlp", "core credential floor", config.ActionBlock, 0, true)
		_ = emitWatchReceipt(opts, logW, frame, config.ActionBlock, "dlp", "core credential floor")
		if frame.ID == nil {
			dropMCPDenial(opts, mcpResponseContentDenialAudit("core credential floor"), "response")
			return true, nil
		}
		return true, writeMCPDenial(opts, mcpResponseContentDenialAudit("core credential floor"), writer, blockResponseReason(frame.ID, "core credential floor enforced in watch-only"))
	}
	found := !verdict.Clean
	observedAction := verdict.Action
	if verdict.Clean {
		observedAction = ""
	} else if observedAction == "" {
		observedAction = sc.ResponseAction()
	}
	taintKinds := ResponseTaintFindingKinds(verdict)
	if verdict.Error != "" {
		observe("mcp_response", verdict.Error, "uninspected", int64(len(line)), false)
	} else if !verdict.Clean {
		names := matchNames(verdict.Matches)
		for _, match := range verdict.DLPMatches {
			names = append(names, match.PatternName)
		}
		observe("mcp_response", "response scanner finding: "+strings.Join(names, ", "), observedAction, 0, false)
	}
	var inventory *tools.ToolInventoryReservation
	if cfg := opts.toolCfg(); cfg != nil {
		toolResult := tools.ScanToolsForMethodContext(opts.warnContext(), line, sc, cfg.WithServerMode(opts.ServerName, opts.ServerBinding, opts.ServerBindingMode, opts.ServerRevision), trackedMethod)
		taintKinds = session.MergeFindingKinds(taintKinds, toolTaintFindingKinds(toolResult, !toolResult.Clean, false))
		if toolResult.IsToolsList && !toolResult.Clean {
			observedAction = config.StricterAction(observedAction, cfg.Action)
			found = true
			if toolResult.ResourceLimit != "" {
				observe("mcp_tools", toolResult.ResourceLimit, "uninspected", int64(len(line)), false)
			} else {
				observe("mcp_tools", "tool definition finding", cfg.Action, 0, false)
			}
		}
		if toolResult.IsToolsList && cfg.Baseline != nil {
			reservation, err := cfg.Baseline.ReserveToolInventory(toolResult.ToolNames, toolResult.ToolDefs)
			if err != nil {
				observe("mcp_tools", "inventory unavailable", "uninspected", int64(len(line)), false)
			} else {
				inventory = reservation
				defer func() {
					if inventory != nil {
						inventory.Release()
					}
				}()
			}
		}
	}
	if cfg := opts.provenanceCfg(); cfg != nil && cfg.Enabled && isToolsListResponse(line) {
		pv := VerifyToolsListProvenance(line, cfg)
		if pv.Block {
			observe("provenance", pv.Error, pv.Action, 0, false)
			found = true
		}
	}
	mediaResult := applyMCPResponseMediaPolicy(line, opts.mediaPolicy(), opts.Transport)
	if mediaResult.Blocked {
		observe("media", mediaResult.BlockReason, config.ActionBlock, 0, false)
		found = true
	} else if mediaResult.Changed {
		observe("media", "response media rewrite", config.ActionStrip, 0, false)
		found = true
	}
	if frame.IsBatch || frame.KeyValidationErr != nil {
		observe("mcp_protocol", "response shape refused by enforced mode", config.ActionBlock, 0, false)
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
		observe("mcp_response", "response fields uninspected", "uninspected", int64(len(line)), false)
	}
	observeMCPResponseFindings(opts, taintKinds)
	pattern := "response observed"
	if len(findings) > 0 {
		pattern += ": " + strings.Join(findings, "; ")
	}
	if err := emitWatchReceipt(opts, logW, frame, config.ActionWarn, "mcp_response", pattern); err != nil && opts.requireReceipts() {
		return true, err
	}
	if err := writeMCPResponseDisposition(opts, mcpDenialAudit{}, writer, line, false); err != nil {
		return found, fmt.Errorf("forwarding watch-only MCP response: %w", err)
	}
	if inventory != nil {
		reservation := inventory
		if opts.toolInventoryDelivery != nil {
			opts.toolInventoryDelivery(func() { _ = reservation.Commit(true) }, reservation.Release)
			inventory = nil
		} else {
			_ = reservation.Commit(true)
		}
	}
	return found, nil
}

func watchCoreFragments(matches []scanner.DLPMatch) bool {
	for _, match := range matches {
		if config.IsCoreDLPPatternName(match.PatternName) || match.IsInspectionLimit() {
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
