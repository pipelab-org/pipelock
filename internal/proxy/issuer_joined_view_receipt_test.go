// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
)

// withRecordedAudit rebuilds the env's proxy around an audit logger whose
// output the test can read and a receipt recorder, using the same config,
// scanner and metrics the requests use.
func (e *delegationEnv) withRecordedAudit(t *testing.T) (*auditLogBuffer, *receiptProxyHelper) {
	t.Helper()
	logs := &auditLogBuffer{}
	logger, err := audit.NewWithStream("json", "stdout", "", true, true, logs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(logger.Close)
	p, err := New(e.cfg, logger, e.sc, e.m)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(p.Close)
	e.p, e.logger = p, logger
	rph := newReceiptProxyHelperWithMetrics(t, e.m)
	t.Cleanup(func() { _ = rph.rec.Close() })
	e.p.receiptEmitterPtr.Store(rph.emitter)
	return logs, rph
}

// TestInterceptJoinedViewAllowIsRecordedAsDLP drives the production intercept
// handler and checks the audit event and receipt each allowance writes.
func TestInterceptJoinedViewAllowIsRecordedAsDLP(t *testing.T) {
	const joinedLayer = "dlp_issuer_joined_view_allow"
	const joinedKind = "issued_joined_view"
	const entropyLayer = "entropy_issuer_query_allow"

	t.Run("joined DLP view allow writes its own event and receipt", func(t *testing.T) {
		first, second := joinedCardHalves()
		query := "wo=" + first + "&site=" + second
		e := newSameOriginEnv(t, func(c *config.Config) { c.FlightRecorder.RequireReceipts = true })
		logs, rph := e.withRecordedAudit(t)
		e.servePage(joinedDetailPath + "?" + query)
		e.visit()
		if got := e.do("agent-one", http.MethodGet, joinedDetailURL(delegationSourceHost, query)); got != http.StatusOK {
			t.Fatalf("status = %d, want 200", got)
		}
		if !strings.Contains(logs.String(), `"event":"dlp_issuer_joined_view_allow"`) {
			t.Fatalf("no joined view audit event in %s", logs.String())
		}
		if strings.Contains(logs.String(), `"event":"entropy_issuer_query_allow"`) {
			t.Fatal("a DLP joined-view allowance was logged as a query entropy allowance")
		}
		if strings.Contains(logs.String(), first+second) {
			t.Fatal("audit log carried the joined value")
		}
		r := rph.requireReceipt(t, joinedLayer)
		if r.ActionRecord.Verdict != config.ActionAllow {
			t.Fatalf("receipt verdict = %q, want allow", r.ActionRecord.Verdict)
		}
		if !strings.Contains(string(r.Ext), `"`+joinedLayer+`":"`+joinedKind+`"`) {
			t.Fatalf("receipt extension = %s", r.Ext)
		}
		if strings.Contains(r.ActionRecord.Target, "?") {
			t.Fatalf("receipt target carried the query: %q", r.ActionRecord.Target)
		}
	})

	t.Run("an entropy-only issuer rescan is not labelled joined", func(t *testing.T) {
		challenge := challengeURL(delegationSourceHost)
		e := newSameOriginEnv(t, func(c *config.Config) { c.FlightRecorder.RequireReceipts = true })
		logs, rph := e.withRecordedAudit(t)
		e.issue(http.StatusFound, challenge)
		if got := e.issueAndFollow(challenge); got != http.StatusFound {
			t.Fatalf("follow-up status = %d, want 302 from upstream", got)
		}
		if strings.Contains(logs.String(), "dlp_issuer_joined_view_allow") {
			t.Fatal("an entropy-only rescan wrote a joined view event")
		}
		if !strings.Contains(logs.String(), `"event":"entropy_issuer_query_allow"`) {
			t.Fatalf("no entropy issuer allow event in %s", logs.String())
		}
		var entropyReceipt bool
		for _, r := range rph.findReceipts(t) {
			if r.ActionRecord.Layer == joinedLayer || strings.Contains(string(r.Ext), joinedKind) {
				t.Fatalf("entropy-only allow produced a joined view receipt: layer=%s ext=%s", r.ActionRecord.Layer, r.Ext)
			}
			if r.ActionRecord.Layer == entropyLayer && r.ActionRecord.Verdict == config.ActionAllow {
				entropyReceipt = true
			}
		}
		if !entropyReceipt {
			t.Fatal("no entropy issuer allow receipt")
		}
	})
}
