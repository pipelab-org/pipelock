// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

const (
	taintScopeAction = "action"
	taintScopeSource = "source"
	taintScopeTask   = "task"
)

// WithTaintRecorder binds forward, fetch, intercepted HTTP, and WebSocket
// traffic to one invocation-owned recorder. The caller owns its lifetime and
// must not share this proxy between independent invocations.
func WithTaintRecorder(rec session.Recorder) Option {
	if isNilSessionRecorder(rec) {
		rec = nil
	}
	return func(p *Proxy) { p.taintRecorder = rec }
}

// sharedTaskSubject reads the subject an invocation already bound to a shared
// recorder. It never binds one: that subject belongs to the invocation owner.
func sharedTaskSubject(rec session.Recorder) string {
	if state, ok := rec.(interface{ TaskSubject() string }); ok {
		return state.TaskSubject()
	}
	return ""
}

func isNilSessionRecorder(rec session.Recorder) bool {
	if rec == nil {
		return true
	}
	v := reflect.ValueOf(rec)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	default:
		return false
	}
}

type taintDecision struct {
	Risk                session.SessionRisk
	Task                session.TaskContext
	ActionClass         session.ActionClass
	Sensitivity         session.ActionSensitivity
	Authority           session.AuthorityKind
	Result              session.PolicyDecisionResult
	ActionRef           string
	TaskOverrideApplied bool
}

func responseTaintSessionKey(cfg *config.Config, agent, clientIP string, auth envelope.ActorAuth) string {
	return ceeSessionKey(cfg, agent, clientIP, auth)
}

func (p *Proxy) resolveTaintAsk(agent, target, method, reason string) (bool, string) {
	switch {
	case p.approver == nil:
		return false, reason + " (no HITL approver)"
	case !p.approver.IsTerminal():
		return false, reason + " (HITL stdin is not a terminal)"
	}
	decision := p.approver.Ask(&hitl.Request{
		Agent:   agent,
		URL:     target,
		Reason:  reason,
		Preview: fmt.Sprintf("%s %s", method, target),
	})
	return decision == hitl.DecisionAllow, reason
}

func observeHTTPResponseTaint(rec session.Recorder, cfg *config.Config, rawURL, contentType, kind string, promptHit bool) {
	var kinds []session.HostileFindingKind
	if promptHit {
		kinds = []session.HostileFindingKind{session.FindingUnattributed}
	}
	observeHTTPResponseFindings(rec, cfg, rawURL, contentType, kind, kinds)
}

func observeHTTPResponseFindings(rec session.Recorder, cfg *config.Config, rawURL, contentType, kind string, kinds []session.HostileFindingKind) {
	rs, ok := rec.(session.RiskState)
	if !ok || cfg == nil || !cfg.Taint.Enabled {
		return
	}
	observation := session.ClassifyHTTPResponseFindings(rawURL, contentType, cfg.Taint.AllowlistedDomains, kinds)
	observation.Source.Kind = kind
	observation.MaxSources = cfg.Taint.RecentSources
	rs.ObserveRisk(observation)
}

// A response's source exposure is recorded in the session recorder when the
// response is received, before any response byte is delivered to the client, on
// every path; finding kinds from a buffered scan are recorded before the scanned
// body is delivered; streaming findings are recorded before the affected event
// is released. Exposure remains recorded if a later check blocks delivery.
//
// httpResponseFindingObserver shares duplicate suppression across these calls
// and the final observation, so EOF and repeated findings do not fill the bounded
// source history with duplicates.
// Calls belong to the response's handler goroutine.
func httpResponseFindingObserver(rec session.Recorder, cfg *config.Config, rawURL, contentType, kind string) func([]session.HostileFindingKind) {
	var observed bool
	var observedTask string
	var previous []session.HostileFindingKind
	return func(kinds []session.HostileFindingKind) {
		merged := session.MergeFindingKinds(previous, kinds)
		var currentTask string
		if state, ok := rec.(session.TaskContextProvider); ok {
			currentTask = state.TaskSnapshot().CurrentTaskID
		}
		if observed && currentTask == observedTask && slices.Equal(previous, merged) {
			return
		}
		observeHTTPResponseFindings(rec, cfg, rawURL, contentType, kind, merged)
		observed, previous, observedTask = true, merged, currentTask
	}
}

func evaluateHTTPTaint(cfg *config.Config, rec session.Recorder, method string, parsedURL *url.URL) taintDecision {
	return evaluateHTTPTaskTaint(cfg, rec, method, parsedURL, nil)
}

type forwardTaskAction struct {
	subject string
	action  session.TaskAction
}

func evaluateHTTPTaskTaint(cfg *config.Config, rec session.Recorder, method string, parsedURL *url.URL, task *forwardTaskAction) taintDecision {
	decision := taintDecision{
		ActionClass: session.ActionClassRead,
		Sensitivity: session.SensitivityNormal,
		Authority:   session.AuthorityUserBroad,
		Result:      session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "taint_disabled"},
	}
	if cfg == nil || !cfg.Taint.Enabled || parsedURL == nil {
		return decision
	}

	if rs, ok := rec.(session.RiskState); ok {
		decision.Risk = rs.RiskSnapshot()
	}
	classified := session.ClassifyHTTPActionWithOptions(method, parsedURL.Path, cfg.Taint.ProtectedPaths, cfg.Taint.ElevatedPaths, session.ClassificationOptions{
		FailSafe: cfg.Taint.FailSafeClassification,
	})
	decision.ActionClass = classified.Class
	decision.Sensitivity = classified.Sensitivity
	decision.ActionRef = httpActionRef(decision.ActionClass, method, parsedURL)
	var matched bool
	if state, ok := rec.(session.TaskPermissionState); ok && task != nil {
		decision.Risk, decision.Task, matched = state.TaskPolicySnapshot(task.subject, task.action)
	} else if tp, ok := rec.(session.TaskContextProvider); ok {
		decision.Task = tp.TaskSnapshot()
	}
	decision.Result = session.PolicyMatrix{Profile: cfg.Taint.Policy}.EvaluateWithOptions(
		decision.Risk.Level, decision.ActionClass, decision.Sensitivity, decision.Authority,
		session.PolicyEvaluateOptions{
			FailSafeClassification:  cfg.Taint.FailSafeClassification,
			ClassificationConfident: classified.Confident,
			CheckTaskPermission:     task != nil,
			TaskPermissionMatched:   matched,
		},
	)
	switch decision.Result.Reason {
	case session.TaskPermissionRequired, session.TaskPermissionGranted:
		return decision
	}
	if tp, ok := rec.(session.TaskContextProvider); ok {
		if runtimeTrustOverrideApplies(tp.RuntimeTrustOverrides(), decision.Task, decision.Risk, decision.ActionRef) {
			decision.Result = session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "taint_runtime_task_override"}
			decision.TaskOverrideApplied = true
			return decision
		}
	}
	if trustOverrideApplies(cfg.Taint.TrustOverrides, decision.Risk, decision.ActionRef) {
		decision.Result = session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: "taint_trust_override"}
	}
	return decision
}

// forwardRequestTaskAction binds the emitted URL, end-to-end headers, and
// body. Unbuffered bodies and trailers cannot satisfy an exact permission.
func forwardRequestTaskAction(req *http.Request, body []byte) session.TaskAction {
	if len(req.Trailer) > 0 || (req.Body != nil && req.Body != http.NoBody && body == nil) {
		return session.TaskAction{}
	}
	h := sha256.New()
	if err := req.Header.Write(h); err != nil {
		return session.TaskAction{}
	}
	_, _ = h.Write([]byte("\r\n"))
	_, _ = h.Write(body)
	return session.TaskAction{Method: req.Method, Destination: req.URL.String(), Digest: hex.EncodeToString(h.Sum(nil))}
}

func (p *Proxy) resolveForwardTaskApproval(rec session.Recorder, task forwardTaskAction, decision *taintDecision, agent string) (string, string) {
	outcome := hitl.OutcomeUnavailable
	if !task.action.Valid() {
		return "task_action_unavailable", "the complete outbound request could not be bound for approval"
	}
	if p.approver != nil {
		outcome = p.approver.AskOutcome(&hitl.Request{
			Agent:        agent,
			URL:          task.action.Destination,
			Reason:       session.TaskPermissionRequired + " (SHA-256 " + task.action.Digest + ")",
			Preview:      task.action.Method + " " + task.action.Destination,
			Confirmation: session.TaskApprovalConfirmation(),
		})
	}
	if outcome != hitl.OutcomeAllow {
		reason, detail := session.TaskApprovalRefusal(outcome)
		if task.subject != "" && p.sessionAPI != nil && p.sessionAPI.currentAPIToken() != "" {
			detail += "; an operator can grant this action using POST /api/v1/sessions/{key}/task; digest " + task.action.Digest
		}
		return reason, detail
	}
	if tp, ok := rec.(session.TaskContextProvider); ok && tp.TaskSnapshot().CurrentTaskID != decision.Task.CurrentTaskID {
		return session.TaskApprovalStale, "the task changed while approval was pending"
	}
	decision.Authority = session.AuthorityOperatorOverride
	decision.Result = session.PolicyDecisionResult{Decision: session.PolicyAllow, Reason: session.TaskApprovalGranted}
	return "", ""
}

func forwardTaskAdmissionCurrent(rec session.Recorder, task forwardTaskAction, decision taintDecision) bool {
	state, ok := rec.(session.TaskPermissionState)
	if !ok {
		return decision.Result.Reason != session.TaskPermissionGranted
	}
	_, current, matched := state.TaskPolicySnapshot(task.subject, task.action)
	return current.CurrentTaskID == decision.Task.CurrentTaskID && (decision.Result.Reason != session.TaskPermissionGranted || matched)
}

func httpActionRef(action session.ActionClass, method string, parsedURL *url.URL) string {
	actionName := strings.ToLower(action.String())
	methodName := strings.ToLower(method)
	if parsedURL == nil {
		return fmt.Sprintf("%s:%s", actionName, methodName)
	}
	requestURI := parsedURL.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	return fmt.Sprintf(
		"%s:%s:%s://%s%s",
		actionName,
		methodName,
		strings.ToLower(parsedURL.Scheme),
		strings.ToLower(parsedURL.Host),
		requestURI,
	)
}

func trustOverrideApplies(overrides []config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	now := time.Now().UTC()
	for _, override := range overrides {
		if !override.ExpiresAt.IsZero() && override.ExpiresAt.Before(now) {
			continue
		}
		if !overrideMatches(override, risk, actionRef) {
			continue
		}
		return true
	}
	return false
}

func overrideMatches(override config.TaintTrustOverride, risk session.SessionRisk, actionRef string) bool {
	switch override.Scope {
	case taintScopeAction:
		if override.ActionMatch == "" || !wildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		if override.SourceMatch != "" && !riskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		return true
	case taintScopeSource:
		if override.SourceMatch == "" || !riskSourceMatches(risk, override.SourceMatch) {
			return false
		}
		if override.ActionMatch != "" && !wildcardMatch(actionRef, override.ActionMatch) {
			return false
		}
		return true
	default:
		return false
	}
}

func runtimeTrustOverrideApplies(overrides []session.TrustOverride, task session.TaskContext, risk session.SessionRisk, actionRef string) bool {
	now := time.Now().UTC()
	for _, override := range overrides {
		if override.Scope != taintScopeTask {
			continue
		}
		if override.TaskID == "" || override.TaskID != task.CurrentTaskID {
			continue
		}
		if !override.ExpiresAt.IsZero() && override.ExpiresAt.Before(now) {
			continue
		}
		if override.ActionMatch != "" && !wildcardMatch(actionRef, override.ActionMatch) {
			continue
		}
		if override.SourceMatch != "" && !riskSourceMatches(risk, override.SourceMatch) {
			continue
		}
		return true
	}
	return false
}

func riskSourceMatches(risk session.SessionRisk, pattern string) bool {
	return wildcardMatch(risk.SecurityOriginURL(), pattern)
}

func wildcardMatch(value, pattern string) bool {
	if value == "" || pattern == "" {
		return false
	}
	if matched, err := path.Match(pattern, value); err == nil && matched {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return value == pattern
	}
	parts := strings.Split(pattern, "*")
	pos := 0
	for i, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(value[pos:], part)
		if idx < 0 {
			return false
		}
		if i == 0 && !strings.HasPrefix(pattern, "*") && idx != 0 {
			return false
		}
		pos += idx + len(part)
	}
	if !strings.HasSuffix(pattern, "*") && parts[len(parts)-1] != "" && !strings.HasSuffix(value, parts[len(parts)-1]) {
		return false
	}
	return true
}
