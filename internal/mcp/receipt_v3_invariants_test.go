// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

// mcpReceiptDelivery describes the client-side observation for one exchange.
type mcpReceiptDelivery struct {
	status          int
	sent, received  []byte
	withheld        bool
	denialDelivered bool
}

func checkMCPReceiptHistory(actions []v3.Action, deliveries ...mcpReceiptDelivery) error {
	type attempt struct {
		id     string
		number int64
	}
	intents := make(map[attempt]v3.Action)
	outcomes := make(map[attempt]v3.Action)
	for _, action := range actions {
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
		phase[key] = action
	}
	for key := range intents {
		if _, exists := outcomes[key]; !exists {
			return fmt.Errorf("action %s attempt %d has no terminal outcome", key.id, key.number)
		}
	}
	for key, outcome := range outcomes {
		intent, exists := intents[key]
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
		if intent.ActionType != outcome.ActionType || intent.Transport != outcome.Transport ||
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
	if blocks > 1 || withheld && completed != 0 && !delivery.denialDelivered {
		return fmt.Errorf("downstream delivery has %d block decisions and %d completions", blocks, completed)
	}
	if completed != 0 && delivery.sent != nil && !bytes.Equal(delivery.received, delivery.sent) {
		return fmt.Errorf("downstream delivery completed with bytes different from what was sent")
	}
	if withheld && delivery.status == http.StatusOK && len(delivery.received) == 0 {
		return fmt.Errorf("withheld downstream delivery returned an empty HTTP 200")
	}
	return nil
}

func TestMCPReceiptHistoryInvariants(t *testing.T) {
	attempt := int64(1)
	intent := v3.Action{ActionID: "reply", Attempt: &attempt, Phase: "intent", EffectBoundary: mcpDownstreamDeliveryBoundary}
	completed := intent
	completed.Phase = "outcome"
	completed.OutcomeClass = "completed"
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
		{name: "recovery without intent", actions: []v3.Action{recovery}},
		{name: "different bytes", actions: []v3.Action{intent, completed}, delivery: mcpReceiptDelivery{sent: []byte("sent")}, want: "different from what was sent"},
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
