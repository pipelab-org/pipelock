// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/ael"
	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/deferred"
	"github.com/luckyPipewrench/pipelock/internal/mcp/transport"
	"github.com/luckyPipewrench/pipelock/internal/scanner"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

// A listener request can produce the bounded kill-switch batch receipts plus
// the input, forwarding, and stream terminal decisions. Individual SSE
// messages take their own reservations.
const (
	nativeMCPPendingRecords = 14 + receipt.DLPWarningSlots
	nativeMCPRequestRecords = maxKillSwitchBatchReceipts + 15 + receipt.DLPWarningSlots
	nativeMCPEventRecords   = 7 + receipt.DLPWarningSlots
)

func (o MCPProxyOpts) admitNativeRequest() (receipt.EmitOpts, error) {
	var admission receipt.EmitOpts
	var err error
	if o.ReceiptGroup != nil && o.ReceiptGroup.Shards != nil {
		admission, err = o.ReceiptGroup.Shards.AdmitNative(receipt.EmitOpts{}, nativeMCPRequestRecords)
	} else {
		// Embedded listeners use the process writer. Its reservation still
		// counts against the group's shared stop coordinator.
		admission, err = o.receiptEmitter().AdmitNative(receipt.EmitOpts{}, nativeMCPRequestRecords)
	}
	if err != nil {
		return receipt.EmitOpts{}, err
	}
	return admission.ReserveNativeTerminal()
}

func (o MCPProxyOpts) nativeWarningContext(ctx context.Context, admission receipt.EmitOpts) (context.Context, func()) {
	e := o.receiptEmitter()
	if o.ReceiptGroup != nil && o.ReceiptGroup.Shards != nil && admission.NativeLease != nil {
		e, _ = o.ReceiptGroup.Shards.SelectedEmitter(admission)
	}
	return receipt.WithDLPWarningBudget(ctx, e, admission)
}

func trackNativeOutcome(tracker *RequestTracker, id json.RawMessage, outcome TrackedRequestOutcome) error {
	if outcome.Receipt.NativeLease == nil {
		tracker.TrackOutcome(id, outcome)
		return nil
	}
	lease, err := outcome.Receipt.NativeLease.Split(nativeMCPPendingRecords)
	if err != nil {
		return err
	}
	outcome.Receipt.NativeLease = lease
	outcome.Receipt.NativeTerminalLease = nil
	outcome.ownsNativeLease = true
	if !tracker.TrackOutcome(id, outcome) {
		lease.Release()
		return errors.New("could not reserve a pending receipt outcome for this request ID")
	}
	return nil
}

func nativeAdmissionDenial(id json.RawMessage, err error) BlockedRequest {
	return BlockedRequest{
		ID: id, IsNotification: isRPCNotification(id),
		LogMessage: err.Error(), ErrorCode: -32007, ErrorMessage: err.Error(),
		ErrorData: mcpBlockReasonData(blockreason.ReceiptEmissionFailed),
	}
}

func writeNativeAdmissionDenial(o MCPProxyOpts, logW io.Writer, out transport.MessageWriter, id json.RawMessage, err error) {
	denial := nativeAdmissionDenial(id, err)
	if denial.IsNotification {
		dropMCPDenial(o, nativeAdmissionAudit(), "input")
		return
	}
	if writeErr := deliverMCPInputResult(o, denial, out); writeErr != nil {
		_, _ = fmt.Fprintf(logW, "pipelock: write capacity refusal: %v\n", writeErr)
	}
}

func nativeAdmissionAudit() mcpDenialAudit {
	return mcpInputGateBlockAudit(scanner.AuditReceiptEmission, mcpReceiptEmissionReason, audit.BlockClassInfrastructureError)
}

func (o MCPProxyOpts) shutdownGrace() time.Duration {
	if o.ListenerShutdownTimeout > 0 {
		return o.ListenerShutdownTimeout
	}
	return 5 * time.Second
}

func (o MCPProxyOpts) nativeCapacity() *ael.Capacity {
	if o.ReceiptGroup != nil && o.ReceiptGroup.Shards != nil {
		return o.ReceiptGroup.Shards.ProcessEmitter().NativeCapacity()
	}
	return o.receiptEmitter().NativeCapacity()
}

func (o MCPProxyOpts) nativeCapacityStopError() error {
	select {
	case <-o.nativeCapacity().Stopped():
		return ael.ErrCapacity
	default:
		return nil
	}
}

// Stop a stdio read that started before capacity was reached. The response
// side remains open to settle replies already tracked against reserved space.
func (o MCPProxyOpts) closeNativeInputOnStop(input io.Reader) func() {
	closer, ok := input.(io.Closer)
	stopped := o.nativeCapacity().Stopped()
	if !ok || stopped == nil {
		return func() {}
	}
	disarm := make(chan struct{})
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		select {
		case <-stopped:
			_ = closer.Close()
		case <-disarm:
		}
	}()
	return func() {
		close(disarm)
		<-joined
	}
}

// Deferred resolution outlives the request input iteration. Transfer its
// slots before registering the hold, then settle them in the callback.
func (o MCPProxyOpts) splitDeferredAdmission() (MCPProxyOpts, func(), error) {
	lease, err := o.nativeAdmission.NativeLease.Split(nativeMCPPendingRecords)
	if err != nil || lease == nil {
		return o, func() {}, err
	}
	o.nativeAdmission.NativeLease = lease
	o.nativeAdmission.NativeTerminalLease = nil
	ctx, finishWarnings := o.nativeWarningContext(o.warnContext(), o.nativeAdmission)
	o.WarnContext = ctx
	return o, func() {
		finishWarnings()
		lease.Release()
	}, nil
}

func watchCapacityDeferrals(ctx context.Context, o MCPProxyOpts) {
	manager := o.deferManager()
	stopped := o.nativeCapacity().Stopped()
	if manager == nil || stopped == nil {
		return
	}
	select {
	case <-stopped:
		manager.ResolveAll(config.ActionBlock, deferred.SourceCancel)
	case <-ctx.Done():
	}
}
