// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/receipt/v3"
)

// confirmMCPResponseEffect retains a tracked request's selected shard. A
// standalone response selects once through emitReceiptDecision instead.
func confirmMCPResponseEffect(logW io.Writer, opts MCPProxyOpts, selected receipt.EmitOpts, decision receipt.EmitOpts) error {
	if !opts.legacyReceiptsRequired() {
		return nil
	}
	decision = withMCPResponseShard(selected, decision)
	_, err := opts.emitReceiptDecision(MCPDecision{Receipt: opts.withReceiptPolicyHash(decision), RequireReceipt: true, RequiredMode: true, Durable: true})
	if err != nil {
		logReceiptEmitFailure(logW, err, true, decision.Verdict)
	}
	return err
}

func confirmMCPCardAcceptance(ctx context.Context, logW io.Writer, opts MCPProxyOpts, selected, evidence receipt.EmitOpts, candidate AgentCardScanResult) (*v3.EffectToken, error) {
	var checks []receipt.EmitOpts
	if candidate.SignatureVerified {
		check := evidence
		check.ActionID = receipt.NewActionID()
		check.Layer, check.Pattern = "a2a_card_signature", "verified key_id="+candidate.SignatureKeyID
		checks = append(checks, check)
	}
	if candidate.FirstSeen || candidate.DriftAdopted {
		evidence.ActionID = receipt.NewActionID()
		evidence.Layer, evidence.Pattern = "a2a_card_drift", "Agent Card baseline accepted"
		checks = append(checks, evidence)
	}
	if !opts.receiptEffects.enabled {
		for _, check := range checks {
			if err := confirmMCPResponseEffect(logW, opts, selected, check); err != nil {
				return nil, err
			}
		}
		return nil, nil
	}
	actions := make([]v3.Action, 0, len(checks))
	for _, check := range checks {
		action, _ := opts.v3EffectAction(withMCPResponseShard(selected, check), mcpDownstreamDeliveryBoundary)
		actions = append(actions, action)
	}
	_, policy := opts.v3EffectAction(evidence, mcpDownstreamDeliveryBoundary)
	return opts.receiptEffects.gate.AdmitBatch(ctx, actions, policy)
}

func withMCPResponseShard(selected, decision receipt.EmitOpts) receipt.EmitOpts {
	decision.ParentActionID = selected.ActionID
	if decision.NativeLease == nil {
		decision = decision.InheritAdmission(selected)
	}
	return decision
}
