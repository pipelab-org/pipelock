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
	e.p.receiptEmitterPtr.Store(rph.emitter)
	return logs, rph
}

// TestInterceptJoinedViewAllowIsRecordedAsDLP drives the production intercept
// handler and checks the audit event and receipt each allowance writes.
func TestInterceptJoinedViewAllowIsRecordedAsDLP(t *testing.T) {
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
		r := rph.requireReceipt(t, issuerJoinedViewReceiptKey)
		if !strings.Contains(string(r.Ext), `"`+issuerJoinedViewReceiptKey+`":"`+string(issuerQueryJoinedView)+`"`) {
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
		for _, r := range rph.findReceipts(t) {
			if r.ActionRecord.Layer == issuerJoinedViewReceiptKey || strings.Contains(string(r.Ext), string(issuerQueryJoinedView)) {
				t.Fatalf("entropy-only allow produced a joined view receipt: layer=%s ext=%s", r.ActionRecord.Layer, r.Ext)
			}
		}
	})
}
