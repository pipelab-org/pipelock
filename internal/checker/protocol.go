// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// Package checker defines content assessments, never authorization decisions.
// The wire contract is documented in docs/checker-protocol.md.
package checker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"
	"unicode/utf8"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// Version is the exact wire version. Incompatible schemas need a new version.
const Version = "pipelock.checker/v1"

// Kind identifies the assessment unit. Action and image are reserved, unsupported
// by the v1 text client; they must never silently be treated as text.
type Kind string

const (
	KindText   Kind = "text"
	KindAction Kind = "action"
	KindImage  Kind = "image"
)

// State uses the scanner assessment vocabulary without depending on the scanner.
type State string

const (
	StateOff         State = "off"
	StateNotAssessed State = "not_assessed"
	StateBenign      State = "benign"
	StateFinding     State = "finding"
	StateIncomplete  State = "incomplete"
)

// Status separates whether assessment happened from its classification.
type Status string

const (
	StatusAssessed   Status = "assessed"
	StatusNotChecked Status = "not_checked"
	// StatusInvalid is local only; it is never a valid wire response status.
	StatusInvalid Status = "invalid"
)

// Classification is a checker's conclusion, not an enforcement action.
type Classification string

const (
	Benign     Classification = "benign"
	Suspicious Classification = "suspicious"
	Abstain    Classification = "abstain"
)

// Reason is a stable failure code. No remote diagnostic text enters errors.
type Reason string

const (
	ReasonUnavailable   Reason = "unavailable"
	ReasonTimeout       Reason = "timeout"
	ReasonCanceled      Reason = "canceled"
	ReasonRefused       Reason = "refused"
	ReasonUnsupported   Reason = "unsupported"
	ReasonOverBudget    Reason = "over_budget"
	ReasonTruncated     Reason = "truncated"
	ReasonMalformed     Reason = "malformed"
	ReasonStaleRevision Reason = "stale_revision"
	ReasonRedirect      Reason = "redirect"
	ReasonIdentity      Reason = "identity_mismatch"
	ReasonTooLarge      Reason = "response_too_large"
	ReasonPolicy        Reason = "invalid_policy"
)

// Part preserves exact UTF-8 content and its order. Role and Representation are
// labels supplied by the extractor, including labels for decoded extra views.
type Part struct {
	ID             string `json:"part_id"`
	Role           string `json:"role"`
	Representation string `json:"representation"`
	Text           string `json:"text"`
}

// ContextValue labels provenance explicitly. Only operator-origin values may be
// authenticated; values observed in tool output always remain untrusted.
type ContextValue struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Origin string `json:"origin"`
	Trust  string `json:"trust"`
}

const (
	OriginOperator     = "operator"
	OriginToolOutput   = "tool_output"
	TrustAuthenticated = "authenticated"
	TrustUntrusted     = "untrusted"
	Complete           = "complete"
	Partial            = "partial"
)

// Completeness describes the entire semantic item, not just the submitted prefix.
type Completeness struct {
	Status string `json:"status"`
	Reason Reason `json:"reason,omitempty"`
}

// Item is immutable for the duration of Check. SubmittedBytes counts UTF-8 text
// bytes across all ordered parts, including extra views; OriginalBytes counts the
// source item before extraction, and can be smaller than SubmittedBytes.
type Item struct {
	ID                string         `json:"item_id"`
	Kind              Kind           `json:"kind"`
	Surface           string         `json:"surface"`
	Transport         string         `json:"transport"`
	Direction         string         `json:"direction"`
	ExtractionVersion string         `json:"extraction_version"`
	Parts             []Part         `json:"parts"`
	OriginalBytes     int64          `json:"original_bytes"`
	SubmittedBytes    int64          `json:"submitted_bytes"`
	Completeness      *Completeness  `json:"completeness"`
	Context           []ContextValue `json:"context,omitempty"`
	// Payload reserves a structured extension point for action/image kinds.
	// Text items must omit it; this client does not interpret reserved payloads.
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Revision is an operator-pinned identity checked against every response.
// A claimed revision is not cryptographic proof of a provider's deployed model.
type Revision struct {
	Checker string `json:"checker"`
	Model   string `json:"model"`
	Adapter string `json:"adapter"`
}

// Request carries exactly one item. InputBinding is SHA-256 of the exact Item
// JSON bytes transmitted, not a provider's reserialization of that object.
type Request struct {
	Version          string          `json:"protocol_version"`
	ID               string          `json:"request_id"`
	PolicyGeneration string          `json:"policy_generation"`
	InputBinding     string          `json:"input_binding"`
	Item             json.RawMessage `json:"item"`
}

// Score carries no implicit cutoff or universal probability interpretation.
type Score struct {
	Value         *float64 `json:"value"`
	Scale         string   `json:"scale"`
	CalibrationID string   `json:"calibration_id"`
}

// Finding identifies a stable reason and optionally the submitted parts it cites.
type Finding struct {
	ReasonID string   `json:"reason_id"`
	PartIDs  []string `json:"part_ids,omitempty"`
}

// Response contains no source offsets, advice, content rewrites or tool calls.
type Response struct {
	Version        string         `json:"protocol_version"`
	RequestID      string         `json:"request_id"`
	ItemID         string         `json:"item_id"`
	InputBinding   string         `json:"input_binding"`
	Revision       Revision       `json:"revision"`
	Completeness   *Completeness  `json:"completeness"`
	Status         Status         `json:"status"`
	Classification Classification `json:"classification,omitempty"`
	Reason         Reason         `json:"reason,omitempty"`
	Score          *Score         `json:"score,omitempty"`
	Findings       []Finding      `json:"findings,omitempty"`
}

// Scale pins score semantics and the inclusive valid range, supplied by the
// adapter/operator contract. It does not determine classification thresholds.
type Scale struct {
	Name          string
	CalibrationID string
	Min           float64
	Max           float64
}

// Policy is a resolved immutable snapshot, not a configuration schema. All
// budgets are explicit. Timeout covers the entire call, including body reads.
type Policy struct {
	Mode             string
	Generation       string
	Revision         Revision
	Timeout          time.Duration
	MaxRequestBytes  int64
	MaxResponseBytes int64
	Scale            *Scale
}

const (
	ModeOff   = "off"
	ModeWarn  = "warn"
	ModeBlock = "block"
)

// Assessment is a typed outcome. Callers own delivery policy and independent
// controls. Response is present only after successful protocol validation.
type Assessment struct {
	State    State
	Status   Status
	Reason   Reason
	Response *Response
}

// Checker assesses one item without modifying it or granting authority.
type Checker interface {
	Check(context.Context, Item, Policy) Assessment
}

func failure(status Status, reason Reason) Assessment {
	state := StateNotAssessed
	if reason == ReasonTruncated {
		state = StateIncomplete
	}
	return Assessment{State: state, Status: status, Reason: reason}
}

func validReason(r Reason) bool {
	switch r {
	case ReasonUnavailable, ReasonTimeout, ReasonCanceled, ReasonRefused, ReasonUnsupported,
		ReasonOverBudget, ReasonTruncated, ReasonMalformed, ReasonStaleRevision:
		return true
	}
	return false
}

func validCompleteness(c *Completeness) bool {
	return c != nil && ((c.Status == Complete && c.Reason == "") ||
		(c.Status == Partial && validReason(c.Reason)))
}

func validRevision(r Revision) bool {
	return r.Checker != "" && r.Model != "" && r.Adapter != ""
}

func validPolicy(p Policy) bool {
	if (p.Mode != ModeWarn && p.Mode != ModeBlock) || p.Generation == "" ||
		!validRevision(p.Revision) || p.Timeout <= 0 || p.MaxRequestBytes <= 0 ||
		p.MaxResponseBytes <= 0 || p.MaxResponseBytes == math.MaxInt64 {
		return false
	}
	return p.Scale == nil || (p.Scale.Name != "" && p.Scale.CalibrationID != "" &&
		finite(p.Scale.Min) && finite(p.Scale.Max) && p.Scale.Min < p.Scale.Max)
}

func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }

func validItem(item Item) bool {
	if !nonemptyUTF8(item.ID, item.Surface, item.Transport, item.Direction, item.ExtractionVersion) || item.OriginalBytes < 0 ||
		len(item.Payload) != 0 ||
		!validCompleteness(item.Completeness) || len(item.Parts) == 0 {
		return false
	}
	seen := make(map[string]bool, len(item.Parts))
	var size int64
	for _, part := range item.Parts {
		if !nonemptyUTF8(part.ID, part.Role, part.Representation) || seen[part.ID] || !utf8.ValidString(part.Text) {
			return false
		}
		seen[part.ID] = true
		size += int64(len(part.Text))
	}
	for _, value := range item.Context {
		if !nonemptyUTF8(value.Name, value.Origin) || !utf8.ValidString(value.Value) ||
			(value.Trust != TrustUntrusted && (value.Trust != TrustAuthenticated || value.Origin != OriginOperator)) {
			return false
		}
	}
	return size == item.SubmittedBytes
}

func nonemptyUTF8(values ...string) bool {
	for _, value := range values {
		if value == "" || !utf8.ValidString(value) {
			return false
		}
	}
	return true
}

// Binding returns the lowercase SHA-256 digest used by the wire protocol.
func Binding(itemJSON []byte) string {
	sum := sha256.Sum256(itemJSON)
	return hex.EncodeToString(sum[:])
}

// DecodeResponse validates an untrusted response against the exact request and
// captured policy. Invalid and not_checked responses never produce benign.
func DecodeResponse(data []byte, req Request, item Item, policy Policy) Assessment {
	if item.Kind != KindText {
		return failure(StatusNotChecked, ReasonUnsupported)
	}
	var response Response
	if !validPolicy(policy) || !validItem(item) || req.Version != Version || req.ID == "" ||
		req.PolicyGeneration != policy.Generation || req.InputBinding != Binding(req.Item) {
		return failure(StatusInvalid, ReasonMalformed)
	}
	encoded, _ := json.Marshal(item) // Item contains only JSON-supported types.
	if string(encoded) != string(req.Item) || int64(len(data)) > policy.MaxResponseBytes {
		return failure(StatusInvalid, ReasonMalformed)
	}
	if err := jsonscan.DecodeStrict(data, &response); err != nil {
		return failure(StatusInvalid, ReasonMalformed)
	}
	if response.Version != Version {
		return failure(StatusInvalid, ReasonUnsupported)
	}
	if response.RequestID != req.ID || response.ItemID != item.ID || response.InputBinding != req.InputBinding {
		return failure(StatusInvalid, ReasonIdentity)
	}
	if response.Revision != policy.Revision {
		return failure(StatusInvalid, ReasonStaleRevision)
	}
	if !validCompleteness(response.Completeness) || !validResult(response, item, policy.Scale) {
		return failure(StatusInvalid, ReasonMalformed)
	}
	result := Assessment{Status: response.Status, Reason: response.Reason, Response: &response}
	if response.Status == StatusNotChecked {
		result.State = StateNotAssessed
	} else {
		switch response.Classification {
		case Benign:
			result.State = StateBenign
		case Suspicious:
			result.State = StateFinding
		case Abstain:
			result.State = StateIncomplete
		}
	}
	// Partial coverage withholds any benign or abstaining conclusion, but a
	// suspicious classification remains a finding: the attack was detected in
	// what the checker did see, and downgrading it would discard that evidence.
	// The partial completeness stays visible on the response.
	partial := item.Completeness.Status != Complete || response.Completeness.Status != Complete || response.Reason == ReasonTruncated
	if partial && result.State != StateFinding {
		result.State = StateIncomplete
	}
	return result
}

func validResult(r Response, item Item, scale *Scale) bool {
	if r.Status == StatusNotChecked {
		return validReason(r.Reason) && r.Classification == "" && r.Score == nil && len(r.Findings) == 0
	}
	if r.Status != StatusAssessed || r.Reason != "" ||
		(r.Classification != Benign && r.Classification != Suspicious && r.Classification != Abstain) ||
		(r.Classification == Benign && len(r.Findings) != 0) {
		return false
	}
	if r.Score != nil && (scale == nil || r.Score.Value == nil || !finite(*r.Score.Value) ||
		r.Score.Scale != scale.Name || r.Score.CalibrationID != scale.CalibrationID ||
		*r.Score.Value < scale.Min || *r.Score.Value > scale.Max) {
		return false
	}
	parts := make(map[string]bool, len(item.Parts))
	for _, p := range item.Parts {
		parts[p.ID] = true
	}
	for _, f := range r.Findings {
		if f.ReasonID == "" {
			return false
		}
		for _, id := range f.PartIDs {
			if !parts[id] {
				return false
			}
		}
	}
	return true
}
