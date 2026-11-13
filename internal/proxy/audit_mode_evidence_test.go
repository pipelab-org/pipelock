// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/killswitch"
	"github.com/luckyPipewrench/pipelock/internal/metrics"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// auditModeObservation is what one audit-mode request produced: the handler
// status, whether the checked bytes were delivered, the upstream call count,
// the audit event types in arrival order, whether any block counter moved,
// and whether a block receipt was written.
type auditModeObservation struct {
	status       int
	delivered    bool
	upstream     int32
	events       string
	blockMetrics string
	blockReceipt bool
}

func (o auditModeObservation) String() string {
	return strings.Join([]string{
		"status=" + strconv.Itoa(o.status),
		"delivered=" + strconv.FormatBool(o.delivered),
		"upstream=" + strconv.FormatInt(int64(o.upstream), 10),
		"events=" + o.events,
		"blockMetrics=" + o.blockMetrics,
		"blockReceipt=" + strconv.FormatBool(o.blockReceipt),
	}, " ")
}

func (o auditModeObservation) matches(want auditModeObservation) bool {
	return o == want
}

type auditModeRig struct {
	proxy    *Proxy
	logs     *bytes.Buffer
	receipts *receiptProxyHelper
}

// newAuditModeRig builds an in-process proxy with enforce false, a JSON audit
// stream, a receipt emitter, and a kill switch taken from the final config.
func newAuditModeRig(t *testing.T, mod func(*config.Config)) *auditModeRig {
	t.Helper()
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.SSRF.IPAllowlist = []string{"127.0.0.0/8", "::1/128"}
	cfg.APIAllowlist = nil
	cfg.ForwardProxy.Enabled = true
	cfg.ForwardProxy.MaxTunnelSeconds = 10
	cfg.ForwardProxy.IdleTimeoutSeconds = 2
	cfg.FetchProxy.TimeoutSeconds = 2
	off := false
	cfg.Enforce = &off
	if mod != nil {
		mod(cfg)
	}
	savedInternal := cfg.Internal
	cfg.ApplyDefaults()
	cfg.Internal = savedInternal
	var logs bytes.Buffer
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, &logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	sc := scanner.MustNew(cfg)
	m := metrics.New()
	p, err := New(cfg, logger, sc, m, WithKillSwitch(killswitch.New(cfg)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	receipts := newReceiptProxyHelperWithMetrics(t, m)
	p.receiptEmitterPtr.Store(receipts.emitter)
	return &auditModeRig{proxy: p, logs: &logs, receipts: receipts}
}

func (r *auditModeRig) observation(t *testing.T, status int, delivered bool, upstream int32) auditModeObservation {
	t.Helper()
	return auditModeObservation{
		status:       status,
		delivered:    delivered,
		upstream:     upstream,
		events:       auditEventTypes(r.logs.String()),
		blockMetrics: auditBlockMetrics(t, r.proxy.metrics),
		blockReceipt: auditBlockReceipt(t, r.receipts),
	}
}

// waitAuditBlockMetric polls until name is among the block counters or the
// deadline passes. A WebSocket frame refusal records the connection counter
// when the relay finishes, which can be after the client has already read
// the close frame.
// auditLogBuffer serializes audit writes with the test's reads. A WebSocket
// relay keeps writing after the client has observed the close frame.
type auditLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *auditLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *auditLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// waitAuditEvents polls until every comma-separated name in required has
// been written, or the deadline passes.
func waitAuditEvents(t *testing.T, logs interface{ String() string }, required string) string {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		got := auditEventTypes(logs.String())
		if auditEventsContain(got, required) {
			return got
		}
		select {
		case <-deadline.C:
			return got
		case <-t.Context().Done():
			return got
		case <-tick.C:
		}
	}
}

func auditEventsContain(got, required string) bool {
	have := map[string]bool{}
	for _, name := range strings.Split(got, ",") {
		if name != "" {
			have[name] = true
		}
	}
	for _, name := range strings.Split(required, ",") {
		if name != "" && !have[name] {
			return false
		}
	}
	return true
}

func waitAuditBlockMetric(t *testing.T, m *metrics.Metrics, name string) string {
	t.Helper()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	for {
		got := auditBlockMetrics(t, m)
		if strings.Contains(got, name) {
			return got
		}
		select {
		case <-deadline.C:
			return got
		case <-t.Context().Done():
			return got
		case <-tick.C:
		}
	}
}

func assertAuditMode(t *testing.T, got, want auditModeObservation) {
	t.Helper()
	if !got.matches(want) {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

func auditEventTypes(logs string) string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] != '{' {
			continue
		}
		var ev struct {
			Event string `json:"event"`
		}
		if err := json.Unmarshal([]byte(line), &ev); err != nil || ev.Event == "" {
			continue
		}
		if seen[ev.Event] {
			continue
		}
		seen[ev.Event] = true
		out = append(out, ev.Event)
	}
	return strings.Join(out, ",")
}

func auditBlockMetrics(t *testing.T, m *metrics.Metrics) string {
	t.Helper()
	families, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, family := range families {
		name := family.GetName()
		for _, metric := range family.GetMetric() {
			if metricValue(metric) <= 0 {
				continue
			}
			if metricHasLabel(metric, "result", "blocked") || metricHasLabel(metric, "verdict", "blocked") ||
				strings.Contains(name, "block") || strings.Contains(name, "denial") {
				names = append(names, name)
				break
			}
		}
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}

func metricValue(metric *dto.Metric) float64 {
	if metric.GetCounter() != nil {
		return metric.GetCounter().GetValue()
	}
	if metric.GetGauge() != nil {
		return metric.GetGauge().GetValue()
	}
	return 0
}

func metricHasLabel(metric *dto.Metric, name, value string) bool {
	for _, label := range metric.GetLabel() {
		if label.GetName() == name && label.GetValue() == value {
			return true
		}
	}
	return false
}

func auditBlockReceipt(t *testing.T, receipts *receiptProxyHelper) bool {
	t.Helper()
	for _, got := range receipts.findReceipts(t) {
		if got.ActionRecord.Verdict == config.ActionBlock {
			return true
		}
	}
	return false
}

func auditOperatorPattern(cfg *config.Config) {
	cfg.DLP.Patterns = append(cfg.DLP.Patterns, config.DLPPattern{
		Name: auditFloorPatternName, Regex: `auditprobe-[0-9]{8}`, Severity: config.SeverityCritical,
	})
}
