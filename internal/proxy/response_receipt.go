// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/mcp"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// confirmResponseDecision confirms a later decision on an admitted response.
// Optional mode retains best-effort recording; required mode confirms every
// configured family before the caller changes state or delivers bytes.
func (p *Proxy) confirmResponseDecision(cfg *config.Config, opts receipt.EmitOpts, deliveries *v3ResponseReceipts) error {
	if p != nil && p.receiptV3 != nil {
		return p.confirmV3ResponseDecision(cfg, opts, deliveries)
	}
	if cfg != nil {
		opts = withReceiptConfig(opts, cfg)
	}
	if cfg != nil && cfg.FlightRecorder.RequireReceipts {
		return p.emitAllowPathReceipt(cfg, opts)
	}
	if p != nil {
		_ = p.emitReceipt(opts)
	}
	return nil
}

func (rp *ReverseProxyHandler) confirmResponseDecision(cfg *config.Config, opts receipt.EmitOpts, deliveries *v3ResponseReceipts) error {
	if rp.owner != nil && rp.owner.receiptV3 != nil {
		return rp.owner.confirmV3ResponseDecision(cfg, opts, deliveries)
	}
	if cfg != nil {
		opts = withReceiptConfig(opts, cfg)
	}
	if cfg != nil && cfg.FlightRecorder.RequireReceipts {
		return rp.emitAllowPathReceipt(cfg, opts)
	}
	_ = rp.emitReceipt(opts)
	return nil
}

// v3ResponseReceipts holds the decisions made before a single HTTP response
// write. The handler settles each decision from that write's actual result.
type v3ResponseReceipts []*v3TransportReceipt

func (r *v3ResponseReceipts) finish(p *Proxy, ctx context.Context, attempted, completed bool) {
	for _, entry := range *r {
		if attempted {
			p.recordTransportOutcome(ctx, receipt.EmitOpts{Transport: entry.action.Transport}, entry, completed)
		} else {
			p.recordTransportNotReleased(ctx, receipt.EmitOpts{Transport: entry.action.Transport}, entry)
		}
	}
	*r = nil
}

func (p *Proxy) confirmV3ResponseDecision(cfg *config.Config, opts receipt.EmitOpts, deliveries *v3ResponseReceipts) error {
	if deliveries == nil {
		return errors.New("response receipt delivery settlement is unavailable")
	}
	opts.Verdict = receipt.NormalizeVerdict(opts.Verdict)
	entry, err := p.confirmTransportReceipt(context.Background(), cfg, opts, boundaryDownstreamDelivery)
	if receiptWriteWithholdsEffect(cfg, err) {
		return err
	}
	if entry != nil {
		*deliveries = append(*deliveries, entry)
	}
	return nil
}

func mediaRewriteReceipt(opts receipt.EmitOpts) receipt.EmitOpts {
	opts.ActionID = receipt.NewActionID()
	opts.Verdict = config.ActionStrip
	opts.Layer = "media_policy"
	opts.Pattern = "image media rewritten"
	return opts
}

func firstReceiptShard(selected, fallback receipt.EmitOpts) receipt.EmitOpts {
	if selected.ShardSelected || selected.NativeLease != nil {
		return selected
	}
	return fallback
}

// a2aResponseDecisionBlocks follows the transport's resolved response policy.
// Positive signature evidence on an already denied card stays best-effort.
func a2aResponseDecisionBlocks(cfg *config.Config, result mcp.A2AScanResult, denyAsk bool) bool {
	if result.Clean {
		return false
	}
	action := result.Action
	if action == "" {
		action = cfg.A2AScanning.Action
	}
	if cfg.ResponseScanning.Enabled {
		action = config.StricterAction(cfg.ResponseScanning.Action, action)
	}
	return (denyAsk && action == config.ActionAsk) || a2aResultBlocks(cfg, action, result)
}
