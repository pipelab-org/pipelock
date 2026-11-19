// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

const (
	mcpV3Upstream = "upstream_send"
	mcpV3Redirect = "redirect_dispatch"
	mcpV3Delivery = "downstream_delivery"
	mcpV3Approval = "approval_prompt"
)

type mcpV3Receipt struct {
	action v3.Action
	policy v3.PolicySnapshot
}

func (o MCPProxyOpts) prepareV3Receipt(opts receipt.EmitOpts) mcpV3Receipt {
	method := firstNonEmpty(opts.MCPMethod, opts.Method)
	actionType := receipt.ActionUnclassified
	sideEffect := receipt.SideEffectNone
	switch {
	case opts.MCPMethod != "":
		actionType = receipt.ClassifyMCPTool(opts.ToolName, opts.MCPMethod)
		sideEffect = receipt.SideEffectFromMCPAction(actionType)
	case opts.Method != "":
		actionType = receipt.ClassifyHTTP(opts.Method)
		sideEffect = receipt.SideEffectFromMethod(opts.Method)
	}
	action := v3.Action{
		ActionID: opts.ActionID, ParentActionID: opts.ParentActionID, RequestID: opts.RequestID,
		ActionType: string(actionType), Actor: firstNonEmpty(opts.Agent, o.AuthorityActor, "pipelock"), Principal: "local",
		Caller: v3.Caller{Authn: "none"},
		Data: v3.Data{
			SideEffectClass: string(sideEffect), Reversibility: string(receipt.ReversibilityFromMethod(opts.Method)),
		},
		Method: method, Target: receipt.SanitizeSignedTarget(opts.Target, nil), Transport: opts.Transport,
		Layer: opts.Layer, Pattern: opts.Pattern, Severity: opts.Severity,
		Verdict: receipt.NormalizeVerdict(opts.Verdict),
	}
	if caller := o.receiptCaller; caller != nil {
		action.Caller = v3.Caller{
			Authn: "mcp_door_verified", Subject: caller.Subject, Resource: caller.Resource,
			Issuer: caller.Issuer, ClientID: caller.ClientID,
		}
	}
	action.SetAttribution(opts)
	hash := opts.PolicyHash
	if hash != "" && !strings.HasPrefix(hash, "sha256:") {
		hash = "sha256:" + hash
	}
	return mcpV3Receipt{action: action, policy: v3.CapturePolicy(hash)}
}

func mcpV3Releasing(verdict string) bool {
	switch receipt.NormalizeVerdict(verdict) {
	case config.ActionAllow, config.ActionWarn, config.ActionForward, config.ActionStrip, config.ActionRedirect:
		return true
	default:
		return false
	}
}

func (o MCPProxyOpts) writeV3Decision(d MCPDecision) error {
	entry := o.prepareV3Receipt(d.Receipt)
	action := entry.action
	action.Phase = "decision"
	switch {
	case mcpV3Releasing(action.Verdict):
		if d.v3Boundary == "" {
			return fmt.Errorf("MCP receipt effect boundary unavailable: %w", ErrReceiptRequired)
		}
		action.EffectBoundary, action.EffectRelation = d.v3Boundary, "before"
		if d.RequireReceipt {
			attempt := int64(1)
			action.Phase, action.Attempt = "intent", &attempt
		}
	case action.Verdict == config.ActionBlock:
		action.EffectBoundary, action.EffectRelation = firstNonEmpty(d.v3Boundary, "none"), "not_attempted"
	default:
		return fmt.Errorf("MCP receipt phase unavailable for verdict %q: %w", action.Verdict, ErrReceiptRequired)
	}
	err := o.ReceiptV3.WriteAction(o.warnContext(), action, entry.policy)
	if err != nil && d.RequireReceipt {
		return fmt.Errorf("%w: %w", ErrReceiptRequired, err)
	}
	if err == nil && d.v3Confirmed != nil && action.Attempt != nil {
		*d.v3Confirmed = mcpV3Receipt{action: action, policy: entry.policy}
	}
	return err
}

// confirmV3Hold records the manager's computed ancestry and decision-time
// authority while the hold is still private.
func (s *deferredReceiptSettlement) confirmV3Hold(o MCPProxyOpts, opts receipt.EmitOpts) func(deferred.HeldAction) error {
	if o.ReceiptV3 == nil {
		return nil
	}
	entry := o.prepareV3Receipt(o.withReceiptPolicyHash(opts))
	return func(held deferred.HeldAction) error {
		action := entry.action
		action.Actor = firstNonEmpty(held.Authority.Actor, action.Actor)
		action.Principal = firstNonEmpty(held.Authority.Principal, action.Principal)
		if held.Authority.SessionID != "" || held.Authority.SessionIDOriginal != "" {
			if action.Session == nil {
				action.Session = &v3.Session{}
			}
			action.Session.ID = held.Authority.SessionID
			action.Session.OriginalID = held.Authority.SessionIDOriginal
		}
		depth := int64(held.CascadeDepth)
		action.Phase, action.Verdict = "hold", config.ActionDefer
		action.EffectBoundary, action.EffectRelation = mcpV3Approval, "before"
		action.Hold = &v3.Hold{
			ID: held.DeferID, CascadeDepth: &depth, Linkage: held.Linkage, Parent: held.ParentDeferID,
			Policy: deferred.ReceiptPolicyString(held.Policy, held.RulePolicy),
		}
		ctx, cancel := context.WithDeadline(o.warnContext(), held.Deadline)
		defer cancel()
		if err := o.ReceiptV3.WriteAction(ctx, action, entry.policy); err != nil {
			return fmt.Errorf("%w: %w", ErrReceiptRequired, err)
		}
		entry.action = action
		s.v3Hold = &entry
		return nil
	}
}

func (s *deferredReceiptSettlement) settleV3Hold(o MCPProxyOpts, res deferred.Resolution) error {
	if s.v3Hold == nil {
		return fmt.Errorf("MCP hold receipt unavailable: %w", ErrReceiptRequired)
	}
	entry := *s.v3Hold
	action := entry.action
	hold := *action.Hold
	hold.ResolutionPolicy, hold.ResolutionSource = hold.Policy, res.ResolutionSource
	hold.Policy = ""
	action.Phase, action.Verdict, action.EffectRelation = "resolution", res.FinalDecision, "after"
	switch res.FinalDecision {
	case config.ActionStepUp, config.ActionAsk:
		action.Verdict = config.ActionAsk
		action.Ask = &v3.Ask{Channel: "approval_api", Observed: true}
	case config.ActionBlock:
		if s.done && s.err == nil && s.decision == config.ActionAllow {
			correction := true
			hold.Correction = &correction
		}
	}
	action.Hold = &hold
	if err := o.ReceiptV3.WriteAction(context.WithoutCancel(o.warnContext()), action, entry.policy); err != nil {
		return fmt.Errorf("%w: %w", ErrReceiptRequired, err)
	}
	return nil
}

func (s *deferredReceiptSettlement) confirmV3Release(o MCPProxyOpts) (*mcpV3Receipt, error) {
	if o.ReceiptV3 == nil {
		return nil, nil
	}
	if s.v3Hold == nil {
		return nil, fmt.Errorf("MCP hold receipt unavailable: %w", ErrReceiptRequired)
	}
	entry := *s.v3Hold
	attempt := int64(1)
	entry.action.Hold, entry.action.Ask = nil, nil
	entry.action.Phase, entry.action.Attempt, entry.action.Verdict = "intent", &attempt, config.ActionAllow
	entry.action.EffectBoundary, entry.action.EffectRelation = mcpV3Upstream, "before"
	if err := o.ReceiptV3.WriteAction(o.warnContext(), entry.action, entry.policy); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrReceiptRequired, err)
	}
	return &entry, nil
}

// confirmV3StreamAdmission confirms the upstream connection before dialing or
// subscribing. The callers report the result of that contact separately.
func (o MCPProxyOpts) confirmV3StreamAdmission(logW io.Writer, method string) (mcpV3Receipt, error) {
	var entry mcpV3Receipt
	if o.ReceiptV3 == nil {
		return entry, nil
	}
	required := o.requireReceipts()
	decision := mcpStreamReceipt(o, method)
	decision.Verdict = config.ActionAllow
	_, err := o.emitReceiptDecision(MCPDecision{
		Receipt: decision, RequireReceipt: required, v3Boundary: mcpV3Upstream, v3Confirmed: &entry,
	})
	if err != nil {
		logReceiptEmitFailure(logW, err, required, decision.Verdict)
		if required {
			return entry, err
		}
	}
	return entry, nil
}

// finish writes the observed result of a confirmed upstream send.
func (o MCPProxyOpts) confirmV3ResponseDelivery(logW io.Writer, opts receipt.EmitOpts, delivery *mcpV3Receipt) error {
	required := o.requireReceipts()
	_, err := o.emitReceiptDecision(MCPDecision{
		v3Boundary: mcpV3Delivery, v3Confirmed: delivery, Receipt: o.withReceiptPolicyHash(opts),
		RequireReceipt: required, RequiredMode: required, Durable: required,
	})
	if err != nil {
		logReceiptEmitFailure(logW, err, required, opts.Verdict)
		if required {
			return err
		}
	}
	return nil
}

// v3MCPChild derives correlation and policy from the request while assigning
// a separate identity to the new gate or delivery.
func v3MCPChild(parent receipt.EmitOpts, layer, reason string) receipt.EmitOpts {
	parent.ParentActionID, parent.ActionID = parent.ActionID, receipt.NewActionID()
	parent.Layer, parent.Pattern = layer, reason
	return parent
}

func emitMCPUpstreamRefusal(opts MCPProxyOpts, logW io.Writer, intent receipt.EmitOpts, bytesTransferred int64, reason string) {
	if opts.ReceiptV3 != nil {
		opts.recordV3MCPRefusal(logW, intent, mcpV3Upstream, reason)
		return
	}
	emitMCPBlockedOutcomeReceipt(opts.receiptEmitter(), opts.v2ReceiptEmitter(), opts.ReceiptGroup, logW, intent, bytesTransferred, reason, opts.requireReceipts())
}

func (o MCPProxyOpts) recordV3MCPRefusal(logW io.Writer, intent receipt.EmitOpts, boundary, reason string) {
	refusal := v3MCPChild(intent, intent.Layer, reason)
	refusal.Verdict = config.ActionBlock
	entry := o.prepareV3Receipt(o.withReceiptPolicyHash(refusal))
	entry.action.Phase, entry.action.EffectBoundary, entry.action.EffectRelation = "decision", boundary, "not_attempted"
	if err := o.ReceiptV3.WriteAction(context.WithoutCancel(o.warnContext()), entry.action, entry.policy); err != nil {
		logReceiptEmitFailure(logW, err, o.requireReceipts(), refusal.Verdict)
	}
}

func (o MCPProxyOpts) writeMCPGeneratedResponse(logW io.Writer, writer transport.MessageWriter, parent receipt.EmitOpts, response []byte, reason string) error {
	if o.ReceiptV3 == nil {
		return writer.WriteMessage(response)
	}
	decision := v3MCPChild(parent, mcpOutcomeLayer, reason)
	decision.Verdict = config.ActionAllow
	decision.Transport = firstNonEmpty(decision.Transport, o.Transport)
	decision.Target = firstNonEmpty(decision.Target, "mcp://response")
	var delivery mcpV3Receipt
	if err := o.confirmV3ResponseDelivery(logW, decision, &delivery); err != nil {
		return err
	}
	return delivery.writeV3Response(o, logW, writer, response)
}

func (r *mcpV3Receipt) writeV3Response(o MCPProxyOpts, logW io.Writer, writer transport.MessageWriter, content []byte) error {
	if r.action.Attempt != nil {
		if err := o.warnContext().Err(); err != nil {
			r.finish(o, logW, false, nil)
			return err
		}
	}
	err := writeMCPResponseDisposition(o, mcpDenialAudit{}, writer, content, false)
	if r.action.Attempt != nil && o.finishV3ResponseDelivery != nil {
		o.finishV3ResponseDelivery(*r, err)
		r.action.Attempt = nil
	} else {
		r.finish(o, logW, true, err)
	}
	return err
}

func (r *mcpV3Receipt) finishRedirect(o MCPProxyOpts, logW io.Writer, result RedirectResult) {
	var dispatchErr error
	if !result.Success {
		dispatchErr = errors.New("redirect handler failed")
	}
	r.finish(o, logW, result.started, dispatchErr)
}

func (r *mcpV3Receipt) finish(o MCPProxyOpts, logW io.Writer, attempted bool, sendErr error) {
	if r == nil || r.action.Attempt == nil {
		return
	}
	action := r.action
	r.action.Attempt = nil
	action.Phase = "outcome"
	switch {
	case !attempted:
		action.Verdict, action.EffectRelation, action.OutcomeClass = config.ActionBlock, "not_attempted", "not_released"
	case sendErr != nil:
		action.EffectRelation, action.OutcomeClass = "unknown", "attempt_unknown"
	default:
		action.EffectRelation, action.OutcomeClass = "after", "completed"
	}
	if err := o.ReceiptV3.WriteAction(context.WithoutCancel(o.warnContext()), action, r.policy); err != nil {
		logReceiptEmitFailure(logW, err, o.requireReceipts(), action.Verdict)
	}
}
