// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
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

func confirmMCPCardAcceptance(ctx context.Context, logW io.Writer, opts MCPProxyOpts, selected receipt.EmitOpts, decision receipt.EmitOpts) error {
	if !opts.receiptEffects.enabled {
		return confirmMCPResponseEffect(logW, opts, selected, decision)
	}
	decision = opts.withReceiptPolicyHash(withMCPResponseShard(selected, decision))
	token, err := opts.admitV3Effect(ctx, decision, mcpDownstreamDeliveryBoundary)
	if err != nil {
		return err
	}
	return confirmMCPV3Effect(ctx, token, true)
}

func withMCPResponseShard(selected, decision receipt.EmitOpts) receipt.EmitOpts {
	decision.ParentActionID = selected.ActionID
	if decision.NativeLease == nil {
		decision = decision.InheritAdmission(selected)
	}
	return decision
}
