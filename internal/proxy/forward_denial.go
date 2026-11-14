// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/blockreason"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

type forwardDenialKind string

const (
	forwardDenialUnclassified                    forwardDenialKind = "unclassified"
	forwardDenialConnectSessionCapacity          forwardDenialKind = "connect_session_capacity"
	forwardDenialConnectInterceptSessionCapacity forwardDenialKind = "connect_intercept_session_capacity"
	forwardDenialForwardSessionCapacity          forwardDenialKind = "forward_session_capacity"
	forwardDenialRequestPolicy                   forwardDenialKind = "request_policy"
)

type forwardDenialMetric int

const (
	forwardDenialMetricRequest forwardDenialMetric = iota + 1
	forwardDenialMetricTunnel
)

type forwardDenialWrite int

const (
	forwardDenialWriteNone forwardDenialWrite = iota
	forwardDenialWriteHTTP
)

// forwardDenialSpec is the forward-handler refusal catalog. It follows the
// MCP denial catalog in shape: a kind, the audit label the call site already
// emits, and a fixed reason. The first entry is the fail-closed fallback for a
// kind that is not listed.
type forwardDenialSpec struct {
	kind          forwardDenialKind
	label         string
	reason        string
	metric        forwardDenialMetric
	write         forwardDenialWrite
	status        int
	block         blockreason.Reason
	freshActionID bool
	class         string
}

var forwardDenialCatalog = [...]forwardDenialSpec{
	{
		kind:   forwardDenialUnclassified,
		label:  scanner.AuditScannerUnavailable,
		reason: "HTTP denial classification unavailable",
		metric: forwardDenialMetricRequest,
		write:  forwardDenialWriteHTTP,
		status: http.StatusServiceUnavailable,
		block:  blockreason.PatternUnavailable,
		class:  audit.BlockClassInfrastructureError,
	},
	{
		kind:   forwardDenialConnectSessionCapacity,
		label:  sessionCapacityLayer,
		reason: session.ErrCapacity.Error(),
		metric: forwardDenialMetricTunnel,
		write:  forwardDenialWriteHTTP,
		status: http.StatusServiceUnavailable,
		block:  blockreason.DataBudget,
		class:  audit.BlockClassProtective,
	},
	{
		kind:          forwardDenialConnectInterceptSessionCapacity,
		label:         sessionCapacityLayer,
		reason:        session.ErrCapacity.Error(),
		metric:        forwardDenialMetricTunnel,
		freshActionID: true,
		class:         audit.BlockClassProtective,
	},
	{
		kind:   forwardDenialForwardSessionCapacity,
		label:  sessionCapacityLayer,
		reason: session.ErrCapacity.Error(),
		metric: forwardDenialMetricRequest,
		write:  forwardDenialWriteHTTP,
		status: http.StatusServiceUnavailable,
		block:  blockreason.DataBudget,
		class:  audit.BlockClassProtective,
	},
	{
		kind:   forwardDenialRequestPolicy,
		label:  blockLayerRequestPolicy,
		metric: forwardDenialMetricRequest,
		class:  audit.BlockClassProtective,
	},
}

// requestPolicyBlockClass is the audit class for an enforced request-policy
// refusal. An unknown or unclassified kind uses the catalog's fail-closed class.
func requestPolicyBlockClass() string {
	spec, ok := forwardDenialSpecFor(forwardDenialRequestPolicy)
	if !ok || spec.class == "" {
		return audit.BlockClassInfrastructureError
	}
	return spec.class
}

func forwardDenialSpecFor(kind forwardDenialKind) (forwardDenialSpec, bool) {
	for _, spec := range forwardDenialCatalog {
		if spec.kind == kind {
			return spec, true
		}
	}
	return forwardDenialCatalog[0], false
}

// forwardDenial is one refusal emission. The handler still decides to refuse.
// Emit is the transport closure that already stamps the receipt shard, the
// policy hash, and the recorded-receipt header.
type forwardDenial struct {
	Kind        forwardDenialKind
	Context     audit.LogContext
	Writer      http.ResponseWriter
	RequestID   string
	Agent       string
	MetricAgent string
	Hostname    string
	Started     time.Time
	ActionID    string
	Emit        func(receipt.EmitOpts)
	Method      string
	Target      string
	Transport   string
}

// emitForwardDenial records one catalogued forward or CONNECT refusal.
// An unknown kind still refuses and still records a refusal, using the
// unclassified entry.
func (p *Proxy) emitForwardDenial(d forwardDenial) {
	spec, _ := forwardDenialSpecFor(d.Kind)
	reason := spec.reason
	class := spec.class
	if class == "" {
		class = audit.BlockClassInfrastructureError
	}
	p.logger.LogBlockedDetail(d.Context, spec.label, reason, audit.BlockDetail{Class: class})
	if spec.metric == forwardDenialMetricTunnel {
		p.metrics.RecordTunnelBlocked(d.MetricAgent)
	} else {
		p.metrics.RecordBlocked(d.Hostname, spec.label, time.Since(d.Started), d.MetricAgent)
	}
	actionID := d.ActionID
	var parent string
	if spec.freshActionID {
		parent = d.ActionID
		actionID = receipt.NewActionID()
	}
	d.Emit(receipt.EmitOpts{
		ActionID:       actionID,
		ParentActionID: parent,
		Verdict:        config.ActionBlock,
		Layer:          spec.label,
		Pattern:        reason,
		Transport:      d.Transport,
		Method:         d.Method,
		Target:         d.Target,
		RequestID:      d.RequestID,
		Agent:          d.Agent,
	})
	if spec.write == forwardDenialWriteHTTP {
		writeBlockedError(d.Writer, blockInfoFor(spec.block, spec.label).WithRequestID(d.RequestID), reason, spec.status)
	}
}
