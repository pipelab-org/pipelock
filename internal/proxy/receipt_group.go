// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/contract/proxydecision"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// receiptGroupRuntime pairs each v1 shard with its v2 emitter. The slice is
// immutable after publication; both emitters write to the same recorder session.
type receiptGroupRuntime struct {
	shards            *receipt.ReceiptShardSet
	v2                []*proxydecision.Emitter
	onRequiredFailure func(error)
}

// WithReceiptShardSet validates and installs the fixed emitters for a group.
// The process shard remains available to legacy lifecycle consumers, while
// traffic emission requires an admission-time shard selection.
func WithReceiptShardSet(shards *receipt.ReceiptShardSet, v2 []*proxydecision.Emitter, onRequiredFailure ...func(error)) (Option, error) {
	if shards == nil || shards.ProcessEmitter() == nil {
		return nil, errors.New("receipt group has no process emitter")
	}
	open, _ := shards.Opening()
	if len(v2) != open.ShardCount {
		return nil, fmt.Errorf("receipt group has %d v2 emitters, want %d", len(v2), open.ShardCount)
	}
	for i, emitter := range v2 {
		if emitter == nil {
			return nil, fmt.Errorf("receipt group v2 shard %d is unavailable", i)
		}
	}
	if len(onRequiredFailure) > 1 {
		return nil, errors.New("receipt group accepts one required failure callback")
	}
	group := &receiptGroupRuntime{shards: shards, v2: append([]*proxydecision.Emitter(nil), v2...)}
	if len(onRequiredFailure) == 1 {
		group.onRequiredFailure = onRequiredFailure[0]
	}
	return func(p *Proxy) {
		p.receiptEmitterPtr.Store(shards.ProcessEmitter())
		p.v2EmitterPtr.Store(group.v2[open.ProcessShardIndex])
		p.noteReceiptSignerKey(shards.ProcessEmitter().SignerKeyHex())
		p.receiptGroupPtr.Store(group)
	}, nil
}

func (g *receiptGroupRuntime) failRequired(err error) {
	if g == nil || err == nil {
		return
	}
	g.shards.MarkUnhealthy(err)
	if g.onRequiredFailure != nil {
		g.onRequiredFailure(err)
	}
}

// A request holds its decision, intent, outcome and supporting receipts on
// one shard for its entire lifetime.
const nativeRequestRecords = 79 + receipt.DLPWarningSlots

const (
	nativeCapacityStopReason = "native_ael_capacity"
	nativeStreamCloseLayer   = "session_close"
)

func (p *Proxy) nativeRequestContext(ctx context.Context, w http.ResponseWriter, admission receipt.EmitOpts) (context.Context, func()) {
	return httpstream.WithCapacityGrace(ctx, w, admission.NativeLease, p.shutdownGraceOrDefault())
}

func isNativeCapacityStop(err error) bool {
	return errors.Is(err, ael.ErrCapacity)
}

// Best-effort streams have no paired intent. Sign a single-phase terminal
// decision instead of claiming an outcome for a nonexistent intent.
func nativeStreamCloseReceipt(opts receipt.EmitOpts) receipt.EmitOpts {
	opts.ActionID = receipt.NewActionID()
	opts.DecisionPhase = ""
	opts.Verdict = config.ActionWarn
	opts.Layer = nativeStreamCloseLayer
	opts.Pattern = nativeCapacityStopReason
	return opts
}

func (p *Proxy) admitReceiptShard() receipt.EmitOpts {
	if group := p.receiptGroupPtr.Load(); group != nil {
		return group.shards.Admit(receipt.EmitOpts{})
	}
	return receipt.EmitOpts{}
}

func (p *Proxy) reserveReceiptAdmission() (receipt.EmitOpts, error) {
	admission := p.admitReceiptShard()
	var err error
	if group := p.receiptGroupPtr.Load(); group != nil {
		admission, err = group.shards.AdmitNative(admission, nativeRequestRecords)
	} else {
		admission, err = p.receiptEmitterPtr.Load().AdmitNative(admission, nativeRequestRecords)
	}
	if err != nil {
		return receipt.EmitOpts{}, err
	}
	return admission.ReserveNativeTerminal()
}

func (p *Proxy) receiptWarningContext(ctx context.Context, admission receipt.EmitOpts) (context.Context, func()) {
	e := p.receiptEmitterPtr.Load()
	if group := p.receiptGroupPtr.Load(); group != nil && admission.NativeLease != nil {
		e, _ = group.shards.SelectedEmitter(admission)
	}
	return receipt.WithDLPWarningBudget(ctx, e, admission)
}

func refuseReceiptAdmission(w http.ResponseWriter, err error) {
	writeHTTPError(w, err.Error(), http.StatusServiceUnavailable)
}

func refuseReceiptCapacity(w http.ResponseWriter, err error) bool {
	if !isNativeCapacityStop(err) {
		return false
	}
	refuseReceiptAdmission(w, ael.ErrCapacity)
	return true
}

func withReceiptShard(opts, selected receipt.EmitOpts) receipt.EmitOpts {
	return opts.InheritAdmission(selected)
}

func receiptShardFromContext(ctx context.Context) receipt.EmitOpts {
	selected, _ := ctx.Value(ctxKeyReceiptShard).(receipt.EmitOpts)
	return selected
}

func (g *receiptGroupRuntime) v2Emitter(opts receipt.EmitOpts) (*proxydecision.Emitter, error) {
	if !opts.ShardSelected || opts.ShardIndex < 0 || opts.ShardIndex >= len(g.v2) || g.v2[opts.ShardIndex] == nil {
		return nil, errors.New("receipt group v2 shard was not selected at admission")
	}
	return g.v2[opts.ShardIndex], nil
}
