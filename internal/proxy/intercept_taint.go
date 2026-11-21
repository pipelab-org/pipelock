// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"io"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const interceptTaintPolicyLayer = "taint_policy"

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
	if ic.ActorAuth == envelope.ActorAuthBound && (ic.Proxy == nil || ic.Proxy.taintRecorder == nil) {
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

type interceptTaintAdmissionOptions struct {
	request     *http.Request
	logContext  audit.LogContext
	actionID    string
	wrapReceipt func(receipt.EmitOpts) receipt.EmitOpts
}

// admitInterceptTaint evaluates the effective outbound request after scanning
// and internal-header removal, before signatures, receipts, or upstream writes.
func admitInterceptTaint(ic *InterceptContext, w http.ResponseWriter, body *[]byte, opts interceptTaintAdmissionOptions) bool {
	r, actx := opts.request, opts.logContext
	decision := evaluateHTTPTaskTaint(ic.taintConfig, ic.taintRecorder, r.Method, r.URL, &ic.taintTask)
	if ic.taint.Result.Reason == session.TaskPermissionRequired && ic.taint.Task.CurrentTaskID != decision.Task.CurrentTaskID {
		decision.Result = session.PolicyDecisionResult{Decision: session.PolicyBlock, Reason: session.TaskApprovalStale}
	}
	if decision.Result.Reason == session.TaskPermissionRequired {
		var bodyBytes []byte
		if body != nil {
			bodyBytes = *body
		}
		if bodyBytes == nil && r.Body != nil && r.Body != http.NoBody && ic.taintConfig != nil && ic.taintConfig.RequestBodyScanning.MaxBodyBytes > 0 {
			maxBytes := ic.taintConfig.RequestBodyScanning.MaxBodyBytes
			// Even with request-body scanning disabled, an exact permission must
			// account for every byte. Reuse the configured request body bound.
			buffered, err := io.ReadAll(io.LimitReader(r.Body, int64(maxBytes)+1))
			_ = r.Body.Close()
			if err == nil && len(buffered) <= maxBytes {
				bodyBytes = buffered
				if body != nil {
					*body = buffered
				}
				r.Body = io.NopCloser(bytes.NewReader(buffered))
				r.ContentLength = int64(len(buffered))
				bodyCopy := buffered
				r.GetBody = func() (io.ReadCloser, error) {
					return io.NopCloser(bytes.NewReader(bodyCopy)), nil
				}
			}
		}
		ic.taintTask.action = forwardRequestTaskAction(r, bodyBytes)
		matched := evaluateHTTPTaskTaint(ic.taintConfig, ic.taintRecorder, r.Method, r.URL, &ic.taintTask)
		if matched.Task.CurrentTaskID != decision.Task.CurrentTaskID {
			matched.Result = session.PolicyDecisionResult{Decision: session.PolicyBlock, Reason: session.TaskApprovalStale}
		}
		decision = matched
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
	refuseInterceptTaint(ic, w, reason, opts)
	return false
}

func writeInterceptTaintRefusal(ic *InterceptContext, w http.ResponseWriter, actx audit.LogContext, reason string) {
	ic.Logger.LogBlocked(actx, interceptTaintPolicyLayer, reason)
	ic.Metrics.RecordTLSRequestBlocked(interceptTaintPolicyLayer)
	writeBlockedError(w, blockInfoFor(blockreason.AuthorityMismatch, interceptTaintPolicyLayer).WithRequestID(ic.RequestID), "blocked: "+reason, http.StatusForbidden)
}

func refuseInterceptTaint(ic *InterceptContext, w http.ResponseWriter, reason string, admission interceptTaintAdmissionOptions) {
	r := admission.request
	opts := receipt.EmitOpts{
		ActionID: admission.actionID, Verdict: config.ActionBlock, Layer: interceptTaintPolicyLayer, Pattern: reason,
		Transport: "intercept", Method: r.Method, Target: r.URL.String(), RequestID: ic.RequestID, Agent: ic.Agent,
	}
	if admission.wrapReceipt != nil {
		opts = admission.wrapReceipt(opts)
	}
	_ = interceptEmitReceipt(ic, opts)
	writeInterceptTaintRefusal(ic, w, admission.logContext, reason)
}

func interceptTaskAdmissionCurrent(ic *InterceptContext) bool {
	switch ic.taint.Result.Reason {
	case session.TaskPermissionGranted, session.TaskApprovalGranted:
		return forwardTaskAdmissionCurrent(ic.taintRecorder, ic.taintTask, ic.taint)
	default:
		return true
	}
}
