// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/envelope"
	"github.com/luckyPipewrench/pipelock/internal/hitl"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
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
// Streams also observe around every client write and flush (OnDelivery), so a
// task that rotates while a stream is open, including between the check before
// a write and the write itself, records the events delivered under it.
//
// httpResponseFindingObserver shares duplicate suppression across these calls
// and the final observation, so EOF and repeated findings do not fill the bounded
// source history with duplicates. It is safe for concurrent use: the reverse
// path calls it from the scanner goroutine and from the client writer.
func httpResponseFindingObserver(rec session.Recorder, cfg *config.Config, rawURL, contentType, kind string) func([]session.HostileFindingKind) {
	var mu sync.Mutex
	var observed bool
	var observedTask string
	var previous []session.HostileFindingKind
	return func(kinds []session.HostileFindingKind) {
		mu.Lock()
		defer mu.Unlock()
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

func evaluateHTTPTaint(cfg *config.Config, rec session.Recorder, method string, parsedURL *url.URL, body bool) taintDecision {
	return evaluateHTTPTaskTaint(cfg, rec, method, parsedURL, body, nil)
}

// requestHasBody reports whether r carries, or may carry, a request body or
// request trailers. Unknown length (chunked or unset) counts as a body so the
// read-method exception cannot be reached by omitting Content-Length.
func requestHasBody(r *http.Request) bool {
	if r == nil {
		return false
	}
	if len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 || r.ContentLength > 0 {
		return true
	}
	return r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody
}

// unknownLengthBodyWait bounds how long a read-shaped HTTP/2 request waits for
// its first body byte or end of stream before taint classifies it. A client
// that ends the stream with an empty DATA frame sends it right after HEADERS.
const unknownLengthBodyWait = 500 * time.Millisecond

// settleUnknownLengthBody resolves a read-shaped HTTP/2 request whose length
// is unknown. A client may send HEADERS without END_STREAM and then end the
// stream with an empty DATA frame, so the server reports an unknown length for
// a request that carries no body, and requestHasBody counts it as one. This
// waits up to wait for the first body byte or end of stream. A stream that
// ends empty is returned as a bodyless request. Data, a read error, or no
// answer within wait keeps the body, and with it the publish classification;
// any byte already read is replayed to later readers.
//
// HTTP/1.1 chunked requests are left alone: they keep counting as bodied.
// Only methods whose class depends on body presence are settled.
func settleUnknownLengthBody(r *http.Request, wait time.Duration) *http.Request {
	if r == nil || r.ProtoMajor < 2 || r.ContentLength >= 0 || len(r.TransferEncoding) > 0 || len(r.Trailer) > 0 ||
		r.Body == nil || r.Body == http.NoBody {
		return r
	}
	switch strings.ToUpper(r.Method) {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
	default:
		return r
	}
	body := peekRequestBody(r.Body)
	settled := *r
	if body.await(wait) && len(body.peeked) == 0 && errors.Is(body.err, io.EOF) {
		settled.Body = http.NoBody
		settled.ContentLength = 0
		return &settled
	}
	settled.Body = body
	return &settled
}

type peekResult struct {
	data []byte
	err  error
}

// peekedRequestBody reads one byte of a request body on a separate goroutine
// so the wait for it can be bounded, and replays that read to later readers.
// Reads after a timed-out wait take the pending result first, so the
// underlying body never has two readers.
type peekedRequestBody struct {
	body   io.ReadCloser
	result chan peekResult
	done   bool
	peeked []byte
	err    error
}

func peekRequestBody(body io.ReadCloser) *peekedRequestBody {
	p := &peekedRequestBody{body: body, result: make(chan peekResult, 1)}
	go func() {
		buf := make([]byte, 1)
		n, err := body.Read(buf)
		p.result <- peekResult{data: buf[:n], err: err}
	}()
	return p
}

// await reports whether the peek finished within wait.
func (p *peekedRequestBody) await(wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case res := <-p.result:
		p.done, p.peeked, p.err = true, res.data, res.err
		return true
	case <-timer.C:
		return false
	}
}

func (p *peekedRequestBody) Read(b []byte) (int, error) {
	if !p.done {
		res := <-p.result
		p.done, p.peeked, p.err = true, res.data, res.err
	}
	if len(p.peeked) > 0 {
		n := copy(b, p.peeked)
		p.peeked = p.peeked[n:]
		return n, nil
	}
	if p.err != nil {
		return 0, p.err
	}
	return p.body.Read(b)
}

func (p *peekedRequestBody) Close() error { return p.body.Close() }

type forwardTaskAction struct {
	subject string
	action  session.TaskAction
	// preSendHeader snapshots the outbound headers before mediation envelope
	// injection adds its own, so an action bound after injection hashes the
	// same headers admission would have bound.
	preSendHeader http.Header
}

// snapshotPreSendHeader records the headers an exact action binds before
// envelope injection changes them. It is a no-op once the action is bound.
func (t *forwardTaskAction) snapshotPreSendHeader(req *http.Request) {
	if t == nil || req == nil || t.action.Valid() {
		return
	}
	t.preSendHeader = req.Header.Clone()
}

// lateRequestTaskAction binds the exact action for a request whose exposure
// arrived after admission, on the same header basis admission uses. When no
// scanner buffer exists, it reads the complete body envelope signing retained,
// bounded by limit; an incomplete or over-limit body yields no action.
func (t *forwardTaskAction) lateRequestTaskAction(req *http.Request, body []byte, limit int) session.TaskAction {
	if body == nil {
		body = retainedRequestBody(req, limit)
	}
	if t.preSendHeader == nil {
		return forwardRequestTaskAction(req, body)
	}
	basis := *req
	basis.Header = t.preSendHeader
	return forwardRequestTaskAction(&basis, body)
}

// retainedRequestBody returns the complete request body a buffering stage
// kept for replay through GetBody, such as envelope signing with request body
// scanning off. It returns nil when no complete copy within limit exists, so
// the action binder keeps refusing that body.
func retainedRequestBody(req *http.Request, limit int) []byte {
	if req == nil || req.GetBody == nil || req.Body == nil || req.Body == http.NoBody || limit <= 0 {
		return nil
	}
	rc, err := req.GetBody()
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, int64(limit)+1))
	if err != nil || len(data) > limit {
		return nil
	}
	if req.ContentLength >= 0 && int64(len(data)) != req.ContentLength {
		return nil
	}
	return data
}

func evaluateHTTPTaskTaint(cfg *config.Config, rec session.Recorder, method string, parsedURL *url.URL, body bool, task *forwardTaskAction) taintDecision {
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
		FailSafe:    cfg.Taint.FailSafeClassification,
		RequestBody: body,
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

// taintAdmission is the decision a request was admitted under and whether
// that admission relied on operator reauthorization.
type taintAdmission struct {
	decision     taintDecision
	reauthorized bool
}

// forwardPreSendTaintRecheck re-evaluates taint for a forward request whose
// admission was decided before a required receipt wait. It returns the live
// decision and a refusal reason when that decision is stricter than the
// admitted one: a block; a new ask on a request admitted without approval; a
// task-permission requirement no current exact grant satisfies (a one-time
// approval of this exact action still covers it); or a task change for an
// admission bound to its task. Approval cannot be requested at this point.
func forwardPreSendTaintRecheck(cfg *config.Config, rec session.Recorder, outReq *http.Request, body []byte, task *forwardTaskAction, admission taintAdmission) (taintDecision, string) {
	after := evaluateHTTPTaskTaint(cfg, rec, outReq.Method, outReq.URL, requestHasBody(outReq), task)
	if after.Result.Reason == session.TaskPermissionRequired && !task.action.Valid() {
		// Exposure arrived after admission, so the exact action was never
		// bound. Bind it now so an existing exact grant can still match; an
		// unbuffered body yields no action and stays refused.
		task.action = task.lateRequestTaskAction(outReq, body, taskActionBodyLimit(cfg))
		after = evaluateHTTPTaskTaint(cfg, rec, outReq.Method, outReq.URL, requestHasBody(outReq), task)
	}
	return after, taskTaintRecheckReason(admission.decision, after, admission.reauthorized)
}

// taskActionBodyLimit is the largest body an exact task action binds, the
// same bound admission uses when it buffers a body for binding.
func taskActionBodyLimit(cfg *config.Config) int {
	if cfg == nil {
		return 0
	}
	return cfg.RequestBodyScanning.MaxBodyBytes
}

// releaseTaintDecision is the taint evidence for a request a pre-send recheck
// let through. Exposure and task always come from the live decision. The
// decision itself comes from the live result when that result allows the
// send, for example an exact grant that matched after late exposure, unless
// a one-time approval of this exact action is what authorizes the release.
func releaseTaintDecision(admitted, after taintDecision) taintDecision {
	released := admitted
	released.Risk = after.Risk
	released.Task = after.Task
	if after.Result.Decision == session.PolicyAllow && admitted.Result.Reason != session.TaskApprovalGranted {
		released.Result = after.Result
		released.Authority = after.Authority
		released.ActionRef = after.ActionRef
		released.TaskOverrideApplied = after.TaskOverrideApplied
	}
	return released
}

// applyTaintEvidence copies a taint decision's session evidence into a receipt.
func applyTaintEvidence(opts *receipt.EmitOpts, d taintDecision) {
	opts.SessionTaintLevel = d.Risk.Level.String()
	opts.SessionContaminated = d.Risk.Contaminated
	opts.RecentTaintSources = d.Risk.Sources
	opts.SessionTaskID = d.Task.CurrentTaskID
	opts.SessionTaskLabel = d.Task.CurrentTaskLabel
	opts.AuthorityKind = d.Authority.String()
	opts.TaintDecision = d.Result.Decision.String()
	opts.TaintDecisionReason = d.Result.Reason
	opts.TaskOverrideApplied = d.TaskOverrideApplied
}

// taskTaintRecheckReason compares a live taint decision with the admitted one
// and returns a refusal reason when the live result is stricter.
func taskTaintRecheckReason(admitted, after taintDecision, reauthorized bool) string {
	taskBound := reauthorized || admitted.Result.Reason == session.TaskPermissionGranted || admitted.Result.Reason == session.TaskApprovalGranted
	switch {
	case after.Result.Decision == session.PolicyBlock:
		return after.Result.Reason
	case taskBound && after.Task.CurrentTaskID != admitted.Task.CurrentTaskID:
		return session.TaskApprovalStale
	case after.Result.Reason == session.TaskPermissionRequired && admitted.Result.Reason != session.TaskApprovalGranted:
		// A stored grant must still match now; an earlier broad approval or
		// an expired grant does not cover a new permission requirement.
		return session.TaskApprovalStale
	case after.Result.Decision == session.PolicyAsk && admitted.Result.Decision == session.PolicyAllow && !reauthorized:
		return after.Result.Reason
	}
	return ""
}
