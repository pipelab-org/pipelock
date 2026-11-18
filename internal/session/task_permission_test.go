// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/hitl"
)

func TestTaskActionValid(t *testing.T) {
	t.Parallel()
	valid := TaskAction{Method: "tools/call", Destination: "server", Tool: "write_file", Digest: strings.Repeat("a", 64)}
	for _, tc := range []struct {
		name   string
		change func(*TaskAction)
	}{
		{name: "exact"},
		{name: "missing_method", change: func(a *TaskAction) { a.Method = "" }},
		{name: "missing_destination", change: func(a *TaskAction) { a.Destination = "" }},
		{name: "short_digest", change: func(a *TaskAction) { a.Digest = a.Digest[1:] }},
		{name: "non_hex_digest", change: func(a *TaskAction) { a.Digest = "z" + a.Digest[1:] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action := valid
			if tc.change != nil {
				tc.change(&action)
			}
			if got, want := action.Valid(), tc.change == nil; got != want {
				t.Errorf("action.Valid() = %t, want %t", got, want)
			}
		})
	}
}

type taskSubjectRecorder struct {
	Recorder
	TaskPermissionState
	subjects []string
}

func (r *taskSubjectRecorder) BindTaskSubject(subject string) {
	r.subjects = append(r.subjects, subject)
}

func TestBindTaskSubjectRequiresVerifiedSubjectAndTaskState(t *testing.T) {
	t.Parallel()
	rec := &taskSubjectRecorder{}
	BindTaskSubject(rec, "")
	BindTaskSubject(struct{ Recorder }{}, "verified-worker")
	BindTaskSubject(rec, "verified-worker")
	if len(rec.subjects) != 1 || rec.subjects[0] != "verified-worker" {
		t.Fatalf("subjects bound = %v, want only the verified worker", rec.subjects)
	}
}

func TestTaskApprovalConfirmationsAreDistinctAndLowercase(t *testing.T) {
	t.Parallel()
	first, second := TaskApprovalConfirmation(), TaskApprovalConfirmation()
	if first == "" || second == "" || first == second || first != strings.ToLower(first) || second != strings.ToLower(second) {
		t.Fatal("approval prompts require distinct, nonempty lowercase confirmations")
	}
}

func TestTaskApprovalRefusalDistinguishesChannelFailures(t *testing.T) {
	t.Parallel()
	const denied = "task_approval_denied"
	const unavailable = "task_approval_unavailable"
	for _, tc := range []struct {
		name, reason, detail string
		outcome              hitl.Outcome
	}{
		{"declined", denied, "the operator did not approve this action", hitl.OutcomeDeclined},
		{"strip", denied, "the operator did not approve this action", hitl.OutcomeStrip},
		{"timeout", "task_approval_timeout", "the approval prompt timed out", hitl.OutcomeTimeout},
		{"input_lost", "task_approval_input_lost", "the approval terminal lost input", hitl.OutcomeInputLost},
		{"unconfirmed", "task_approval_unconfirmed", "the response did not confirm this one-time prompt", hitl.OutcomeUnconfirmed},
		{"not_a_terminal", unavailable, "this action is outside the granted task and approval input is not a terminal", hitl.OutcomeNonTerminal},
		{"no_channel", unavailable, "this action is outside the granted task and no approval channel is available", hitl.OutcomeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, detail := TaskApprovalRefusal(tc.outcome)
			if reason != tc.reason || detail != tc.detail {
				t.Errorf("refusal = (%q, %q), want (%q, %q)", reason, detail, tc.reason, tc.detail)
			}
		})
	}
}

func TestTaskPermissionMatrixUsesExactMatchAfterHostileExposure(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		match    bool
		decision PolicyDecision
		reason   string
	}{
		{"matched", true, PolicyAllow, TaskPermissionGranted},
		{"unmatched", false, PolicyAsk, TaskPermissionRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := (PolicyMatrix{}).EvaluateWithOptions(TaintExternalHostile, ActionClassWrite, SensitivityProtected, AuthorityUserBroad,
				PolicyEvaluateOptions{ClassificationConfident: true, CheckTaskPermission: true, TaskPermissionMatched: tc.match})
			if got.Decision != tc.decision || got.Reason != tc.reason {
				t.Errorf("decision = %v, want %s with reason %q", got, tc.decision, tc.reason)
			}
		})
	}
}
