// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

// mcpReceiptDelivery describes the client-side observation for one exchange.
type mcpReceiptDelivery struct {
	status              int
	sent, received      []byte
	withheldPayload     []byte
	withheld            bool
	denialDelivered     bool
	expectedCompletions int
}

func checkMCPReceiptHistory(actions []v3.Action, deliveries ...mcpReceiptDelivery) error {
	type attempt struct {
		id     string
		number int64
	}
	intents := make(map[attempt]int)
	outcomes := make(map[attempt]int)
	for index, action := range actions {
		if action.Phase != "intent" && action.Phase != "outcome" {
			continue
		}
		if action.Attempt == nil {
			return fmt.Errorf("%s %s has no attempt", action.ActionID, action.Phase)
		}
		key := attempt{action.ActionID, *action.Attempt}
		phase := outcomes
		if action.Phase == "intent" {
			phase = intents
		}
		if _, exists := phase[key]; exists {
			return fmt.Errorf("action %s attempt %d has duplicate %s records", key.id, key.number, action.Phase)
		}
		phase[key] = index
	}
	for key := range intents {
		if _, exists := outcomes[key]; !exists {
			return fmt.Errorf("action %s attempt %d has no terminal outcome", key.id, key.number)
		}
	}
	for key, outcomeIndex := range outcomes {
		outcome := actions[outcomeIndex]
		intentIndex, exists := intents[key]
		if outcome.OutcomeClass == "not_released" {
			if outcome.Verdict != "block" || outcome.EffectRelation != "not_attempted" {
				return fmt.Errorf("action %s attempt %d has a malformed refusal", key.id, key.number)
			}
			if !exists {
				continue
			}
		}
		if !exists {
			return fmt.Errorf("action %s attempt %d has an outcome without its intent", key.id, key.number)
		}
		if intentIndex >= outcomeIndex {
			return fmt.Errorf("action %s attempt %d has an outcome before its intent", key.id, key.number)
		}
		intent := actions[intentIndex]
		// Durable repair can reduce a not-released outcome to standalone
		// evidence even when the failed append left its intent visible.
		parentMatches := intent.ParentActionID == outcome.ParentActionID ||
			(outcome.OutcomeClass == "not_released" && outcome.ParentActionID == "")
		if !parentMatches || intent.ActionType != outcome.ActionType || intent.Transport != outcome.Transport ||
			intent.RequestID != outcome.RequestID ||
			intent.Method != outcome.Method || intent.Target != outcome.Target || intent.EffectBoundary != outcome.EffectBoundary {
			return fmt.Errorf("action %s attempt %d has inconsistent effect fields", key.id, key.number)
		}
	}
	for _, delivery := range deliveries {
		if err := checkMCPReceiptDelivery(actions, delivery); err != nil {
			return err
		}
	}
	return nil
}

func checkMCPReceiptDelivery(actions []v3.Action, delivery mcpReceiptDelivery) error {
	var blocks, completed int
	withheld := delivery.withheld
	for _, action := range actions {
		if action.EffectBoundary != mcpDownstreamDeliveryBoundary {
			continue
		}
		switch {
		case action.Phase == "decision" && action.Verdict == "block":
			blocks++
			withheld = true
		case action.Phase == "outcome" && action.OutcomeClass == "completed":
			completed++
		case action.Phase == "outcome" && action.OutcomeClass == "not_released":
			withheld = true
		}
	}
	maxCompleted := max(1, delivery.expectedCompletions)
	if withheld && !delivery.denialDelivered {
		maxCompleted = 0
	}
	if blocks > 1 || completed > maxCompleted ||
		(delivery.expectedCompletions > 0 && completed != delivery.expectedCompletions) {
		return fmt.Errorf("downstream delivery has %d block decisions and %d completions", blocks, completed)
	}
	if (delivery.expectedCompletions > 0 || completed != 0) && delivery.sent != nil && !bytes.Equal(delivery.received, delivery.sent) {
		return fmt.Errorf("downstream delivery completed with bytes different from what was sent")
	}
	if withheld && len(delivery.withheldPayload) > 0 && bytes.Contains(delivery.received, delivery.withheldPayload) {
		return fmt.Errorf("withheld upstream payload reached the client")
	}
	if withheld && delivery.status == http.StatusOK && len(delivery.received) == 0 {
		return fmt.Errorf("withheld downstream delivery returned an empty HTTP 200")
	}
	return nil
}

// mcpWireObservation binds an actual write to the signed history visible
// at the sink before writing. A stream can contain multiple messages with the
// same RPC ID, so each match consumes a distinct signed attempt.
type mcpWireObservation struct {
	message                     []byte
	before                      []v3.Action
	boundary, parent, requestID string
	outcome                     string
}

func checkMCPWireObservations(actions []v3.Action, boundary string, observations []mcpWireObservation) error {
	if err := checkMCPReceiptHistory(actions); err != nil {
		return err
	}
	type identity struct {
		actionID, parent, requestID, boundary string
		attempt                               int64
	}
	key := func(a v3.Action) identity {
		return identity{a.ActionID, a.ParentActionID, a.RequestID, a.EffectBoundary, *a.Attempt}
	}
	outcomes := make(map[identity]string)
	for _, a := range actions {
		if a.Phase == "outcome" && a.EffectBoundary == boundary && a.OutcomeClass != "not_released" {
			outcomes[key(a)] = a.OutcomeClass
		}
	}
	for i, observed := range observations {
		if observed.boundary != boundary || len(observed.message) == 0 {
			return fmt.Errorf("wire message %d has invalid observation", i+1)
		}
		if observed.outcome == "completed" {
			var frame struct {
				ID    json.RawMessage
				Error json.RawMessage
			}
			if err := json.Unmarshal(observed.message, &frame); err != nil || canonicalID(frame.ID) != observed.requestID {
				return fmt.Errorf("wire message %d has wrong RPC envelope: %s", i+1, observed.message)
			}
			if len(frame.Error) > 0 {
				var detail struct {
					Code    *int
					Message string
				}
				if err := json.Unmarshal(frame.Error, &detail); err != nil || detail.Code == nil || detail.Message == "" {
					return fmt.Errorf("wire message %d has invalid RPC error: %s", i+1, frame.Error)
				}
			}
		}
		var matched identity
		for _, a := range observed.before {
			if a.Phase != "intent" || a.Attempt == nil || a.EffectBoundary != boundary ||
				a.RequestID != observed.requestID || a.ParentActionID != observed.parent || outcomes[key(a)] != observed.outcome {
				continue
			}
			if matched.actionID != "" {
				return fmt.Errorf("wire message %d has multiple unmatched prior intents", i+1)
			}
			matched = key(a)
		}
		if matched.actionID == "" {
			return fmt.Errorf("wire message %d has no matching prior intent and outcome", i+1)
		}
		for _, a := range observed.before {
			if a.Phase == "outcome" && a.Attempt != nil && key(a) == matched {
				return fmt.Errorf("wire message %d had an outcome before the write", i+1)
			}
		}
		delete(outcomes, matched)
	}
	if len(outcomes) != 0 {
		return fmt.Errorf("%s has %d outcomes with no wire observation", boundary, len(outcomes))
	}
	return nil
}

func TestMCPReceiptHistoryInvariants(t *testing.T) {
	attempt := int64(1)
	intent := v3.Action{ActionID: "reply", Attempt: &attempt, Phase: "intent", EffectBoundary: mcpDownstreamDeliveryBoundary}
	completed := intent
	completed.Phase = "outcome"
	completed.OutcomeClass = "completed"
	wrongParent, wrongRequest := completed, completed
	wrongParent.ParentActionID = "different-parent"
	wrongRequest.RequestID = "different-request"
	recovery := completed
	recovery.OutcomeClass, recovery.Verdict, recovery.EffectRelation = "not_released", "block", "not_attempted"
	block := v3.Action{Phase: "decision", Verdict: "block", EffectBoundary: mcpDownstreamDeliveryBoundary}
	for _, tc := range []struct {
		name     string
		actions  []v3.Action
		delivery mcpReceiptDelivery
		want     string
	}{
		{name: "missing terminal", actions: []v3.Action{intent}, want: "no terminal outcome"},
		{name: "duplicate terminal", actions: []v3.Action{intent, completed, completed}, want: "duplicate outcome"},
		{name: "duplicate block", actions: []v3.Action{block, block}, want: "2 block decisions"},
		{name: "completed blocked delivery", actions: []v3.Action{block, intent, completed}, want: "1 block decisions"},
		{name: "missing intent", actions: []v3.Action{completed}, want: "without its intent"},
		{name: "outcome before intent", actions: []v3.Action{completed, intent}, want: "before its intent"},
		{name: "wrong parent", actions: []v3.Action{intent, wrongParent}, want: "inconsistent effect fields"},
		{name: "wrong request", actions: []v3.Action{intent, wrongRequest}, want: "inconsistent effect fields"},
		{name: "recovery without intent", actions: []v3.Action{recovery}},
		{name: "missing completed stream delivery", actions: []v3.Action{intent, completed}, delivery: mcpReceiptDelivery{expectedCompletions: 2}, want: "1 completions"},
		{name: "different bytes", actions: []v3.Action{intent, completed}, delivery: mcpReceiptDelivery{sent: []byte("sent")}, want: "different from what was sent"},
		{name: "withheld payload", actions: []v3.Action{block, intent, completed}, delivery: mcpReceiptDelivery{withheldPayload: []byte("upstream"), received: []byte("denial\nupstream"), denialDelivered: true}, want: "withheld upstream payload"},
		{name: "empty HTTP success", actions: []v3.Action{block}, delivery: mcpReceiptDelivery{status: http.StatusOK}, want: "empty HTTP 200"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMCPReceiptHistory(tc.actions, tc.delivery)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, expected %q", err, tc.want)
			}
		})
	}
}

// Ensure a previous write cannot satisfy admission for a later same-ID reply.
func TestMCPReceiptWireObservationInvariants(t *testing.T) {
	attempt := int64(1)
	intent := v3.Action{Phase: "intent", RequestID: "1", ActionID: "first", EffectBoundary: mcpDownstreamDeliveryBoundary, Attempt: &attempt}
	outcome := intent
	outcome.Phase, outcome.OutcomeClass = "outcome", "completed"
	secondIntent, secondOutcome := intent, outcome
	secondIntent.ActionID, secondOutcome.ActionID = "second", "second"
	history := []v3.Action{intent, outcome, secondIntent, secondOutcome}
	observed := mcpWireObservation{message: []byte(clientRPCReply), boundary: mcpDownstreamDeliveryBoundary, requestID: "1", outcome: "completed"}
	first, second := observed, observed
	first.before, second.before = history[:1], history[:3]
	if err := checkMCPWireObservations(history, mcpDownstreamDeliveryBoundary, []mcpWireObservation{first, second}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		writes     []mcpWireObservation
	}{
		{"extra completion", "no wire observation", []mcpWireObservation{first}},
		{"missing second intent", "no matching prior intent", []mcpWireObservation{first, first}},
		{"late observation", "outcome before the write", []mcpWireObservation{first, {message: second.message, boundary: second.boundary, requestID: second.requestID, outcome: second.outcome, before: history}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMCPWireObservations(history, mcpDownstreamDeliveryBoundary, tc.writes)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("checker returned %v, want %q", err, tc.want)
			}
		})
	}
}
