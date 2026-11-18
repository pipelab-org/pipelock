// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/hitl"
)

const (
	TaskPermissionRequired = "task_permission_required"
	TaskPermissionGranted  = "task_permission_granted"
	TaskApprovalGranted    = "task_approval_granted"
	TaskApprovalStale      = "task_approval_stale"
)

// TaskAction identifies the effect-bearing parts of a request. Digest covers
// its arguments or payload. A display name or a partial match is insufficient.
type TaskAction struct {
	Method      string `json:"method"`
	Destination string `json:"destination"`
	Tool        string `json:"tool,omitempty"`
	Digest      string `json:"digest"`
}

func (a TaskAction) Valid() bool {
	if a.Method == "" || a.Destination == "" || len(a.Digest) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(a.Digest)
	return err == nil
}

// TaskPermission is installed by an authenticated operator into one live
// task generation. The sink derives the bound subject from its own identity.
type TaskPermission struct {
	Action    TaskAction `json:"action"`
	ExpiresAt time.Time  `json:"expires_at"`
}

// TaskPermissionState exposes task permission decisions to transport adapters.
type TaskPermissionState interface {
	BindTaskSubject(subject string)
	TaskPolicySnapshot(subject string, action TaskAction) (SessionRisk, TaskContext, bool)
}

// BindTaskSubject records a verified transport subject on the live recorder.
func BindTaskSubject(rec Recorder, subject string) {
	if state, ok := rec.(TaskPermissionState); ok && subject != "" {
		state.BindTaskSubject(subject)
	}
}

// TaskApprovalConfirmation identifies a single input prompt independently
// from the action digest, including on retries of the exact same action.
func TaskApprovalConfirmation() string {
	return strings.ToLower(rand.Text())
}

// TaskApprovalRefusal returns a machine reason and the detail visible to the
// caller. Only an actual answer on an active channel can report denial.
func TaskApprovalRefusal(outcome hitl.Outcome) (reason, detail string) {
	switch outcome {
	case hitl.OutcomeDeclined, hitl.OutcomeStrip:
		return "task_approval_denied", "the operator did not approve this action"
	case hitl.OutcomeTimeout:
		return "task_approval_timeout", "the approval prompt timed out"
	case hitl.OutcomeInputLost:
		return "task_approval_input_lost", "the approval terminal lost input"
	case hitl.OutcomeUnconfirmed:
		return "task_approval_unconfirmed", "the response did not confirm this one-time prompt"
	case hitl.OutcomeNonTerminal:
		return "task_approval_unavailable", "this action is outside the granted task and approval input is not a terminal"
	default:
		return "task_approval_unavailable", "this action is outside the granted task and no approval channel is available"
	}
}
