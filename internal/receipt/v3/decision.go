// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

type effect struct {
	ActionType string
	Transport  string
	Method     string
	Target     string
	Boundary   string
}

func actionEffect(a Action) effect {
	return effect{a.ActionType, a.Transport, a.Method, a.Target, a.EffectBoundary}
}

func releases(verdict string) bool {
	switch verdict {
	case "allow", "warn", "strip", "forward", "redirect":
		return true
	default:
		return false
	}
}

func releasingBoundary(boundary string) bool {
	return boundary != "none" && boundary != "approval_prompt"
}

func actionShape(a Action, required bool) bool {
	if (a.Phase == "intent" || a.Phase == "outcome") != (a.Attempt != nil) ||
		(a.Phase == "outcome") != (a.OutcomeClass != "") ||
		(a.Phase == "hold" || a.Phase == "resolution") != (a.Hold != nil) {
		return false
	}
	if a.Hold != nil && a.Hold.Correction != nil &&
		(!*a.Hold.Correction || a.Phase != "resolution" || a.Verdict != "block") {
		return false
	}
	if !askShape(a) {
		return false
	}
	switch a.Phase {
	case "decision":
		switch a.Verdict {
		case "block":
			return a.EffectRelation == "not_attempted"
		case "ask":
			return a.EffectBoundary == "hook_execution" && a.EffectRelation == "before"
		default:
			return !required && releases(a.Verdict) && releasingBoundary(a.EffectBoundary) &&
				(a.EffectRelation == "before" || a.EffectRelation == "after" || a.EffectRelation == "unknown")
		}
	case "intent":
		return releases(a.Verdict) && releasingBoundary(a.EffectBoundary) && a.EffectRelation == "before"
	case "outcome":
		return outcomeShape(a)
	case "hold":
		return (a.Verdict == "ask" || a.Verdict == "defer") &&
			a.EffectBoundary == "approval_prompt" && a.EffectRelation == "before"
	case "resolution":
		if a.EffectBoundary != "approval_prompt" {
			return false
		}
		switch a.Verdict {
		case "allow", "ask":
			return a.EffectRelation == "after"
		case "block":
			return a.EffectRelation == "after" || a.EffectRelation == "not_attempted" || a.EffectRelation == "unknown"
		}
	}
	return false
}

func askShape(a Action) bool {
	if a.Verdict != "ask" {
		return a.Ask == nil
	}
	if a.Ask == nil {
		return false
	}
	if a.Phase == "decision" {
		return a.Ask.Channel == "host_prompt" && !a.Ask.Observed
	}
	return a.Ask.Channel == "approval_api" && a.Ask.Observed
}

func outcomeShape(a Action) bool {
	if a.OutcomeClass == "not_released" {
		return a.Verdict == "block" && a.EffectRelation == "not_attempted"
	}
	if !releases(a.Verdict) {
		return false
	}
	switch a.OutcomeClass {
	case "completed", "failed_after_attempt":
		return a.EffectRelation == "after"
	case "failed_before_attempt":
		return a.EffectRelation == "not_attempted"
	case "attempt_unknown":
		return a.EffectRelation == "unknown"
	}
	return false
}

// decisionPiece is an incremental recognizer for one decision in one connected
// segment. Its zero value is the start of a decision.
type decisionPiece struct {
	State           string
	HoldID          string
	FirstResolution string
	Attempt         int64
	Effect          effect
	IntentVerdict   string
	Retryable       bool
}

func (p *decisionPiece) advance(a Action, unknownStart bool) bool {
	if p.State == "" && unknownStart && !p.inferPrefix(a) {
		return false
	}
	switch a.Phase {
	case "decision":
		if p.State != "" {
			return false
		}
		switch a.Verdict {
		case "block":
			p.State = "blocked"
		case "ask":
			p.State = "asked_unobserved"
		default:
			p.State = "allowed_effect_unrecorded"
		}
		return true
	case "hold":
		if p.State != "" {
			return false
		}
		p.State, p.HoldID = "pending", Digest([]byte(a.Hold.ID))
		return true
	case "resolution":
		return p.resolve(a)
	default:
		return p.attempt(a)
	}
}

func (p *decisionPiece) inferPrefix(a Action) bool {
	switch a.Phase {
	case "resolution":
		p.HoldID, p.State = Digest([]byte(a.Hold.ID)), "pending"
		if a.Hold.Correction != nil {
			p.FirstResolution, p.State = "allow", "outcome_unknown"
		}
	case "intent", "outcome":
		// A prefix of standalone refusals can precede any attempt.
		// Track only the last one, without iterating over skipped attempts.
		p.Attempt = *a.Attempt - 1
		if p.Attempt != 0 {
			p.Effect, p.State, p.Retryable = actionEffect(a), "not_released", true
		}
		if a.Phase == "outcome" && a.OutcomeClass != "not_released" {
			if !releasingBoundary(a.EffectBoundary) {
				return false
			}
			p.Attempt, p.Effect = *a.Attempt, actionEffect(a)
			p.IntentVerdict, p.State, p.Retryable = a.Verdict, "outcome_unknown", false
		}
	}
	return true
}

func (p *decisionPiece) resolve(a Action) bool {
	if p.Attempt != 0 || p.HoldID == "" || Digest([]byte(a.Hold.ID)) != p.HoldID {
		return false
	}
	prior := p.FirstResolution
	if prior == "ask" || (prior != "" && a.Verdict != "block") ||
		(a.Hold.Correction != nil) != (prior == "allow" && a.Verdict == "block") {
		return false
	}
	if prior == "" {
		p.FirstResolution = a.Verdict
	}
	switch a.Verdict {
	case "allow":
		p.State = "outcome_unknown"
	case "ask":
		p.State = "stepped_up"
	case "block":
		p.State = "blocked"
	}
	return true
}

func (p *decisionPiece) attempt(a Action) bool {
	if p.Attempt != 0 && p.Effect != actionEffect(a) {
		return false
	}
	if p.IntentVerdict != "" {
		if a.Phase != "outcome" || *a.Attempt != p.Attempt ||
			(a.OutcomeClass != "not_released" && a.Verdict != p.IntentVerdict) {
			return false
		}
		p.IntentVerdict = ""
	} else {
		canStart := p.State == "" || p.Retryable ||
			(p.Attempt == 0 && p.FirstResolution == "allow" && p.State == "outcome_unknown")
		if !canStart || *a.Attempt != p.Attempt+1 ||
			(a.Phase != "intent" && a.OutcomeClass != "not_released") {
			return false
		}
		p.Attempt, p.Effect = *a.Attempt, actionEffect(a)
	}
	p.Retryable = false
	if a.Phase == "intent" {
		p.IntentVerdict, p.State = a.Verdict, "outcome_unknown"
		return true
	}
	switch a.OutcomeClass {
	case "failed_before_attempt":
		p.State, p.Retryable = "failed", true
	case "failed_after_attempt":
		p.State = "failed"
	case "attempt_unknown":
		p.State = "outcome_unknown"
	case "not_released":
		p.State, p.Retryable = "not_released", true
	default:
		p.State = a.OutcomeClass
	}
	return true
}

// AppraisePiece returns the final state of a connected piece of understood
// actions. required reports whether the stream gated the corresponding action.
func AppraisePiece(actions []Action, required []bool, unknownStart bool) (string, bool) {
	if len(actions) == 0 || len(actions) != len(required) {
		return "", false
	}
	var piece decisionPiece
	for i, action := range actions {
		if !actionShape(action, required[i]) || !piece.advance(action, unknownStart) {
			return "", false
		}
	}
	return piece.State, true
}
