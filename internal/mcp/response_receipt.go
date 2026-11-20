// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"io"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// confirmMCPResponseEffect retains a tracked request's selected shard. A
// standalone response selects once through emitReceiptDecision instead.
func confirmMCPResponseEffect(logW io.Writer, opts MCPProxyOpts, selected receipt.EmitOpts, decision receipt.EmitOpts, deliveries *[]mcpV3Receipt) error {
	if !opts.requireReceipts() {
		return nil
	}
	decision = withMCPResponseShard(selected, decision)
	var delivery mcpV3Receipt
	_, err := opts.emitReceiptDecision(MCPDecision{
		v3Boundary: mcpV3Delivery, v3Confirmed: &delivery, Receipt: opts.withReceiptPolicyHash(decision),
		RequireReceipt: true, RequiredMode: true, Durable: true,
	})
	if err != nil {
		logReceiptEmitFailure(logW, err, true, decision.Verdict)
	}
	if delivery.action.Attempt != nil {
		*deliveries = append(*deliveries, delivery)
	}
	return err
}

func withMCPResponseShard(selected, decision receipt.EmitOpts) receipt.EmitOpts {
	decision.ParentActionID = selected.ActionID
	if decision.NativeLease == nil {
		decision = decision.InheritAdmission(selected)
	}
	return decision
}
