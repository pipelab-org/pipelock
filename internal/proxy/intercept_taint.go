// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func initInterceptTaint(ic *InterceptContext, r *http.Request) {
	ic.taintConfig = ic.Config
	ic.taintRecorder = ic.Recorder
	if ic.Proxy != nil {
		if ic.Proxy.taintRecorder != nil {
			ic.taintRecorder = ic.Proxy.taintRecorder
		}
		// Tunnels retain their scanner/identity admission snapshot. Taint is
		// request-scoped: load its live policy without replacing the recorder
		// or forgetting exposure acquired before a reload.
		if live := ic.Proxy.CurrentConfig(); live != nil && live != ic.Config {
			cfg := ic.Config.Clone()
			cfg.Taint = live.Taint
			ic.taintConfig = cfg
		}
	}
	if ic.ActorAuth == envelope.ActorAuthBound {
		ic.taintTask.subject = "forward:" + ic.Agent
		session.BindTaskSubject(ic.taintRecorder, ic.taintTask.subject)
	}
	ic.taint = evaluateHTTPTaskTaint(ic.taintConfig, ic.taintRecorder, r.Method, r.URL, &ic.taintTask)
}

func withInterceptTaint(ic *InterceptContext, opts receipt.EmitOpts) receipt.EmitOpts {
	if ic.taintConfig == nil {
		return opts
	}
	opts.SessionTaintLevel = ic.taint.Risk.Level.String()
	opts.SessionContaminated = ic.taint.Risk.Contaminated
	opts.RecentTaintSources = ic.taint.Risk.Sources
	opts.SessionTaskID = ic.taint.Task.CurrentTaskID
	opts.SessionTaskLabel = ic.taint.Task.CurrentTaskLabel
	opts.AuthorityKind = ic.taint.Authority.String()
	opts.TaintDecision = ic.taint.Result.Decision.String()
	opts.TaintDecisionReason = ic.taint.Result.Reason
	opts.TaskOverrideApplied = ic.taint.TaskOverrideApplied
	return opts
}

func interceptReceiptConfig(ic *InterceptContext) *config.Config {
	if ic.taintConfig != nil {
		return ic.taintConfig
	}
	return ic.Config
}

// admitInterceptTaint evaluates the effective outbound request after scanning
// and internal-header removal, before signatures, receipts, or upstream writes.
func admitInterceptTaint(ic *InterceptContext, w http.ResponseWriter, r *http.Request, actx audit.LogContext, actionID string, body []byte) bool {
	ic.taintTask.action = forwardRequestTaskAction(r, body)
	decision := evaluateHTTPTaskTaint(ic.taintConfig, ic.taintRecorder, r.Method, r.URL, &ic.taintTask)
	if ic.taint.Result.Reason == session.TaskPermissionRequired && ic.taint.Task.CurrentTaskID != decision.Task.CurrentTaskID {
		decision.Result = session.PolicyDecisionResult{Decision: session.PolicyBlock, Reason: session.TaskApprovalStale}
	}
	ic.taint = decision
	if decision.Result.Decision == session.PolicyAllow {
		return true
	}
	ic.Logger.LogTaintDecision(actx, audit.TaintDecision{
		TaintLevel: decision.Risk.Level.String(), ActionClass: decision.ActionClass.String(),
		Sensitivity: decision.Sensitivity.String(), Authority: decision.Authority.String(),
		Decision: decision.Result.Decision.String(), Reason: decision.Result.Reason,
		SourceURL: decision.Risk.SecurityOriginURL(), SourceKind: decision.Risk.SecurityOriginKind(),
	})
	p := ic.Proxy
	if p == nil {
		p = &Proxy{}
	}
	reason := decision.Result.Reason
	if decision.Result.Decision == session.PolicyAsk {
		ic.taintRequiresReauth = true
		if reason == session.TaskPermissionRequired {
			var detail string
			reason, detail = p.resolveForwardTaskApproval(ic.taintRecorder, ic.taintTask, &ic.taint, ic.Agent)
			if reason == "" {
				return true
			}
			ic.taint.Result = session.PolicyDecisionResult{Decision: session.PolicyBlock, Reason: reason}
			reason += " (" + detail + ")"
		} else {
			var approved bool
			approved, reason = p.resolveTaintAsk(ic.Agent, r.URL.String(), r.Method, reason)
			if approved {
				ic.taint.Authority = session.AuthorityOperatorOverride
				return true
			}
		}
	}
	refuseInterceptTaint(ic, w, r, actx, actionID, reason)
	return false
}

func refuseInterceptTaint(ic *InterceptContext, w http.ResponseWriter, r *http.Request, actx audit.LogContext, actionID, reason string) {
	ic.Logger.LogBlocked(actx, "taint_policy", reason)
	ic.Metrics.RecordTLSRequestBlocked("taint_policy")
	_ = interceptEmitReceipt(ic, receipt.EmitOpts{
		ActionID: actionID, Verdict: config.ActionBlock, Layer: "taint_policy", Pattern: reason,
		Transport: "intercept", Method: r.Method, Target: r.URL.String(), RequestID: ic.RequestID, Agent: ic.Agent,
	})
	writeBlockedError(w, blockInfoFor(blockreason.AuthorityMismatch, "taint_policy").WithRequestID(ic.RequestID), "blocked: "+reason, http.StatusForbidden)
}

func interceptTaskAdmissionCurrent(ic *InterceptContext) bool {
	switch ic.taint.Result.Reason {
	case session.TaskPermissionGranted, session.TaskApprovalGranted:
		return forwardTaskAdmissionCurrent(ic.taintRecorder, ic.taintTask, ic.taint)
	default:
		return true
	}
}
