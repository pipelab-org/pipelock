//go:build enterprise

// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Elastic-2.0
// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package dashboard

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/evidenceview"
	"github.com/luckyPipewrench/pipelock/internal/license"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

// --- Route-gating enumerator: every new route is 403 without the agents feature
// AND 403 when authorize rejects ---

func TestHandler_NewRouteGating(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	writeReceiptsToDir(t, dir, buildDashboardChain(t, priv, 2))

	gatedPaths := []string{
		"/agents",
		"/agent/" + testActor,
		"/session/" + testSessionID + "/receipt/0",
	}

	t.Run("no_feature", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir: dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: func(string) bool { return false },
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: no-feature status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})

	t.Run("nil_feature", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir: dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: nil-feature status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})

	t.Run("authorize_rejects", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir: dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: allowAgentsFeature,
			Authorize:  func(*http.Request) error { return errors.New("denied") },
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: authorize-reject status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
			if strings.Contains(rec.Body.String(), "Scorecard") || strings.Contains(rec.Body.String(), "agent-card") {
				t.Errorf("path %s: forbidden response leaked evidence body", path)
			}
		}
	})

	t.Run("wrong_tier", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir: dir,
			TrustedKeys: map[string]TrustedKey{
				keyHex: {Source: trustedKeySource},
			},
			HasFeature: func(feature string) bool {
				// Has "fleet" but not "agents".
				return feature == license.FeatureFleet
			},
		})
		for _, path := range gatedPaths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusForbidden {
				t.Errorf("path %s: wrong-tier status = %d, want %d", path, rec.Code, http.StatusForbidden)
			}
		}
	})
}

// --- Agents route renders agent groups ---

func TestHandler_AgentsRendersGroups(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	// Assert the CLAIM, not the page title. The page keeps its navigational
	// name; what had to change is the identity claim it made about a v1 label.
	if !strings.Contains(body, "Identity not established by v1 receipts") {
		t.Fatal("roster must state that a v1 receipt does not establish identity")
	}
	if !strings.Contains(body, "recorded labels rather than proven identities") {
		t.Fatal("roster lead must describe the values as recorded labels")
	}
	if !strings.Contains(body, "with loaded evidence") {
		t.Fatal("body should contain the agent-count summary line")
	}
	if !strings.Contains(body, testActor) {
		t.Fatalf("body should contain agent name %q", testActor)
	}
	// Verify bounded rollup counts are shown, not aggregate labels.
	if !strings.Contains(body, "chains intact") {
		t.Fatal("body should show 'chains intact' rollup label")
	}
	if !strings.Contains(body, "chains broken") {
		t.Fatal("body should show 'chains broken' rollup label")
	}
	// CSP headers set by gate.
	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, contentSecurityPolicy) || !strings.Contains(got, "script-src 'self' 'nonce-") {
		t.Fatalf("CSP = %q, want dashboard base policy plus script nonce", got)
	}
}

func TestHandler_AgentsDescribesGroupsAsRecordedLabels(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})

	for _, path := range []string{"/agents", "/evidence"} {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, want %d; body=%s", path, rec.Code, http.StatusOK, rec.Body.String())
		}

		body := rec.Body.String()
		for _, want := range []string{
			"Identity not established by v1 receipts",
			"Recorded label",
		} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s body missing %q: %s", path, want, body)
			}
		}
	}
}

func TestHandler_AgentsEmptyStateExplainsReceiptSource(t *testing.T) {
	t.Parallel()

	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir: t.TempDir(),
		HasFeature: allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{
		"The roster lists labels recorded on loaded receipts",
		"Identity not established by v1 receipts",
		"No labels or receipts are loaded",
		"--receipt-dir",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("agents empty body missing %q: %s", want, body)
		}
	}
}

func TestHandler_AgentsHostileEvidenceEscapedAndNoAggregateGreen(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Actor = hostileScript
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})

	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
		HasFeature:  allowAgentsFeature,
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, "/agents", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, hostileScript) {
		t.Fatal("agents response contains raw script tag")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Fatal("agents response should contain HTML-escaped script text")
	}
	for _, banned := range []string{"healthy", "clean", "all clear", "everything verified", "fully verified"} {
		if strings.Contains(strings.ToLower(body), banned) {
			t.Fatalf("agents response contains aggregate-green wording %q", banned)
		}
	}
}

// --- Agent detail route ---

func TestHandler_AgentDetail(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})

	t.Run("found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/"+testActor, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), testActor) {
			t.Fatal("body should contain agent name")
		}
	})

	t.Run("not_found", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/nonexistent", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("nested_path_404", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/"+testActor+"/extra", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("nested agent path status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("empty_agent_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/agent/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("empty agent id status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

// --- Investigator route ---

func TestHandler_Investigator(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	receipts := buildDashboardChain(t, priv, 3)
	writeReceiptsToDir(t, dir, receipts)
	firstPath := "/session/" + testSessionID + "/receipt/" + receipts[0].ActionRecord.ActionID
	lastPath := "/session/" + testSessionID + "/receipt/" + receipts[2].ActionRecord.ActionID
	trusted := map[string]TrustedKey{keyHex: {Source: trustedKeySource}}

	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})

	t.Run("found_action_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, firstPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		if !strings.Contains(body, "Receipt Detail") {
			t.Fatal("body should contain investigator heading")
		}
		if !strings.Contains(body, "allow") {
			t.Fatal("body should show the verdict")
		}
	})

	t.Run("found_second_action_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, lastPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("not_found_action_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/missing-action-id", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("unknown_action_id", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/receipt/abc", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	t.Run("malformed_receipt_paths_404", func(t *testing.T) {
		paths := []string{
			"/session/" + testSessionID + "/receipt/" + receipts[0].ActionRecord.ActionID + "/extra",
			"/session/" + testSessionID + "/receipt/%2f0",
			"/session/" + testSessionID + "/receipt/%2e%2e",
		}
		for _, path := range paths {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequestWithContext(
				context.Background(), http.MethodGet, path, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("path %s status = %d, want %d; body=%s", path, rec.Code, http.StatusNotFound, rec.Body.String())
			}
		}
	})

	t.Run("path_traversal_rejected", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/../receipt/0", nil))
		// The security property: a "../" path must never be served as a valid
		// investigator page (never 200 with receipt content). Go's ServeMux
		// cleans the path and redirects it away (301 on Go <=1.25, 307 on Go
		// >=1.26); a 404 is also acceptable. Assert the property, not one exact
		// redirect code, so a future net/http redirect-code change cannot flip
		// this from green to red.
		if rec.Code == http.StatusOK {
			t.Fatalf("path traversal was served (200); must be redirected away or 404. body=%s", rec.Body.String())
		}
		isRedirect := rec.Code >= 300 && rec.Code < 400
		if !isRedirect && rec.Code != http.StatusNotFound {
			t.Fatalf("path traversal status = %d, want a 3xx redirect or 404", rec.Code)
		}
	})

	t.Run("missing_receipt_segment", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID+"/notreceipt/0", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("bad sub-path status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

// --- Investigator hostile evidence render: attacker-controlled fields are HTML-escaped ---

func TestHandler_InvestigatorHostileEvidenceEscaped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	r.ActionRecord.Target = hostileScript
	r.ActionRecord.Pattern = hostileImage
	r.ActionRecord.Verdict = hostileScript
	r.ActionRecord.Intent = hostileJSON
	r.ActionRecord.SessionTaintLevel = "<b>high</b>"
	r.ActionRecord.RecentTaintSources = []session.TaintSourceRef{{URL: "<script>src</script>", Kind: "test"}}
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})
	receiptPath := "/session/" + testSessionID + "/receipt/" + resigned.ActionRecord.ActionID

	t.Run("raw_view_escapes", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir:   dir,
			TrustedKeys:  map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
			HasFeature:   allowAgentsFeature,
			AuthorizeRaw: allowRawAccess,
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, receiptPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		if strings.Contains(body, hostileScript) {
			t.Fatal("investigator response contains raw script tag")
		}
		if strings.Contains(body, hostileImage) {
			t.Fatal("investigator response contains raw image injection")
		}
		if strings.Contains(body, hostileJSON) {
			t.Fatal("investigator response contains raw script-breaking JSON payload")
		}
		// HTML-escaped versions should be present.
		if !strings.Contains(body, "&lt;script&gt;") {
			t.Fatal("investigator should contain HTML-escaped script text")
		}
	})

	t.Run("metadata_view_redacts_target", func(t *testing.T) {
		handler := New(Options{
			TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
			ReceiptDir:  dir,
			TrustedKeys: map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
			HasFeature:  allowAgentsFeature,
			// No AuthorizeRaw => metadata view.
		})
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, receiptPath, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		body := rec.Body.String()
		// Target must be redacted in metadata view — it was set to hostileScript.
		// The redaction placeholder must be present instead of the raw target.
		if !strings.Contains(body, redactedDestination) {
			t.Fatal("metadata view should show the redaction placeholder for Target")
		}
		// The raw hostile target must not appear (even HTML-escaped, the Target
		// field value should be replaced by the redacted placeholder).
		if strings.Contains(body, hostileScript) {
			t.Fatal("metadata view must not contain the raw hostile target")
		}
		// The redacted view banner should be present.
		if !strings.Contains(body, "Metadata view") {
			t.Fatal("metadata view should show the redaction banner")
		}
		// Taint sources raw length should be cleared.
		// The taint source count detail should not expose source URLs.
		if strings.Contains(body, "&lt;script&gt;src&lt;/script&gt;") {
			t.Fatal("metadata view must not leak taint source URLs")
		}
	})
}

func TestHandler_InvestigatorMetadataRedactsRawExplanationFields(t *testing.T) {
	t.Parallel()

	const secret = "metadata-only-" + "marker"
	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	r := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 13, 0, 0, 0, time.UTC))
	// The secret lives ONLY in the attacker/agent-controllable fields the
	// metadata view redacts. Scanner/config fields carry benign labels that must
	// stay visible.
	r.ActionRecord.Target = "https://api.vendor.example/" + secret
	r.ActionRecord.Pattern = "pattern-" + secret
	r.ActionRecord.Intent = "intent-" + secret
	r.ActionRecord.Layer = "dlp"
	r.ActionRecord.Severity = "high"
	r.ActionRecord.DataClassesIn = []string{"pii"}
	r.ActionRecord.DataClassesOut = []string{"credential"}
	r.ActionRecord.TaintDecisionReason = "source-" + secret
	r.ActionRecord.RecentTaintSources = []session.TaintSourceRef{{
		URL:  "https://source.vendor.example/" + secret,
		Kind: "url",
	}}
	r.ActionRecord.Redaction = &receipt.RedactionSummary{
		TotalRedactions: 1,
		ByClass:         map[string]int{"aws": 1},
	}
	r.ActionRecord.Shield = &receipt.ShieldSummary{
		Pipeline:      "html",
		TotalRewrites: 1,
	}
	resigned, err := signAlteredReceipt(r, priv)
	if err != nil {
		t.Fatalf("signAlteredReceipt: %v", err)
	}
	writeReceiptsToDir(t, dir, []receipt.Receipt{resigned})
	receiptPath := "/session/" + testSessionID + "/receipt/" + resigned.ActionRecord.ActionID

	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
		HasFeature:  allowAgentsFeature,
		// No AuthorizeRaw => metadata view.
	})
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(
		context.Background(), http.MethodGet, receiptPath, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, secret) {
		t.Fatalf("metadata investigator leaked raw explanation secret %q in body: %s", secret, body)
	}
	if !strings.Contains(body, redactedDestination) {
		t.Fatal("metadata investigator should show redaction placeholder")
	}
	// The metadata view must still explain WHY: benign scanner/config semantics
	// stay visible (proves the redaction did not over-strip the investigator).
	for _, want := range []string{"dlp", "high", "pii", "credential"} {
		if !strings.Contains(body, want) {
			t.Fatalf("metadata investigator dropped decision semantics %q; body=%s", want, body)
		}
	}
}

// --- Bounded filter tests ---

func writeReceiptsToDirWithSession(t *testing.T, dir string, sessionID string, receipts []receipt.Receipt) {
	t.Helper()
	rec := newTestRecorder(t, dir, nil)
	for i, r := range receipts {
		if err := rec.Record(recorder.Entry{
			SessionID: sessionID,
			Type:      testReceiptEntryType,
			EventKind: string(r.ActionRecord.ActionType),
			Transport: r.ActionRecord.Transport,
			Summary:   "receipt",
			Detail:    r,
		}); err != nil {
			t.Fatalf("Record(%d): %v", i, err)
		}
	}
	_ = rec.Close()
}

func buildChainForAgent(t *testing.T, priv ed25519.PrivateKey, agentName, sessionID string, count int) []receipt.Receipt {
	t.Helper()
	chain := make([]receipt.Receipt, 0, count)
	prevHash := receipt.GenesisHash
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)

	for i := range count {
		ar := receipt.ActionRecord{
			Version:         receipt.ActionRecordVersion,
			ActionID:        receipt.NewActionID(),
			ActionType:      receipt.ActionRead,
			Timestamp:       base.Add(time.Duration(i) * time.Second),
			Principal:       testPrincipal,
			Actor:           agentName,
			Target:          testTarget,
			SideEffectClass: receipt.SideEffectExternalRead,
			Reversibility:   receipt.ReversibilityFull,
			PolicyHash:      testPolicyHash,
			Verdict:         "allow",
			SessionID:       sessionID,
			Transport:       testTransport,
			Method:          http.MethodGet,
			Layer:           "allowlist",
			Pattern:         "api.vendor.example",
			ChainPrevHash:   prevHash,
			ChainSeq:        uint64(i),
		}
		r, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		hash, err := receipt.ReceiptHash(r)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		chain = append(chain, r)
		prevHash = hash
	}
	return chain
}

func TestHandler_BoundedFilter(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)

	// Create two sessions with different agents.
	chainA := buildChainForAgent(t, priv, "agent-a", "session-a", 2)
	writeReceiptsToDirWithSession(t, dir, "session-a", chainA)

	chainB := buildChainForAgent(t, priv, "agent-b", "session-b", 2)
	writeReceiptsToDirWithSession(t, dir, "session-b", chainB)

	trusted := map[string]TrustedKey{keyHex: {Source: trustedKeySource}}

	model := NewReadModel(Options{
		ReceiptDir:  dir,
		TrustedKeys: trusted,
	})

	t.Run("no_filter_returns_all", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) < 2 {
			t.Fatalf("expected at least 2 agent groups, got %d", len(groups))
		}
	})

	t.Run("agent_filter_selects", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Agent: "agent-a"})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) != 1 {
			t.Fatalf("expected 1 agent group, got %d", len(groups))
		}
		if groups[0].Agent != "agent-a" {
			t.Fatalf("Agent = %q, want agent-a", groups[0].Agent)
		}
	})

	t.Run("unknown_filter_values_fail_closed", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Verdict: "invalid", Chain: "bogus"})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		if len(groups) != 0 {
			t.Fatalf("unknown filter values should match no groups; got %d", len(groups))
		}
	})

	t.Run("chain_intact_filter", func(t *testing.T) {
		groups, err := model.Agents(FilterSpec{Chain: chainIntact})
		if err != nil {
			t.Fatalf("Agents: %v", err)
		}
		// Both agents have intact chains (signed properly).
		if len(groups) < 2 {
			t.Fatalf("chain=intact should match both agents; got %d", len(groups))
		}
	})
}

// --- Preset pre-fill + query-param override ---

func TestHandler_FilterPresets(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	presets := map[string]FilterSpec{
		"blocks-only": {Verdict: verdictBlock, Chain: chainBroken},
	}

	model := NewReadModel(Options{
		ReceiptDir:    dir,
		TrustedKeys:   trusted,
		FilterPresets: presets,
	})

	t.Run("preset_resolves", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=blocks-only", nil)
		f := model.ResolveFilter(req)
		if f.Verdict != verdictBlock {
			t.Fatalf("Verdict = %q, want %q", f.Verdict, verdictBlock)
		}
		if f.Chain != chainBroken {
			t.Fatalf("Chain = %q, want %q", f.Chain, chainBroken)
		}
	})

	t.Run("explicit_overrides_preset", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=blocks-only&verdict=allow", nil)
		f := model.ResolveFilter(req)
		// Explicit verdict should win; but since we check "if all explicit are empty, use preset"
		// the explicit verdict="allow" means we DON'T use the preset at all.
		if f.Verdict != verdictAllow {
			t.Fatalf("Verdict = %q, want %q", f.Verdict, verdictAllow)
		}
	})

	t.Run("unknown_preset_ignored", func(t *testing.T) {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/agents?preset=nonexistent", nil)
		f := model.ResolveFilter(req)
		if f.Verdict != "" {
			t.Fatalf("Verdict = %q, want empty for unknown preset", f.Verdict)
		}
	})
}

// --- No-license and wrong-tier negative tests (comprehensive) ---

func TestHandler_NoLicenseAllRoutes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	allPaths := []string{
		"/",
		"/agents",
		"/agent/test",
		"/session/test",
		"/session/test/receipt/0",
		"/exemptions",
	}

	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary", ReceiptDir: dir,
	})
	for _, path := range allPaths {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, path, nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("path %s: no-license status = %d, want %d", path, rec.Code, http.StatusForbidden)
		}
	}
}

// --- ReadModel.ReceiptDetail tests ---

func TestReadModel_ReceiptDetail(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	pub, priv := generateDashboardKey(t)
	keyHex := hex.EncodeToString(pub)
	receipts := buildDashboardChain(t, priv, 3)
	writeReceiptsToDir(t, dir, receipts)

	model := NewReadModel(Options{
		ReceiptDir:  dir,
		TrustedKeys: map[string]TrustedKey{keyHex: {Source: trustedKeySource}},
	})

	t.Run("found", func(t *testing.T) {
		exp, found, err := model.ReceiptDetail(testSessionID, receipts[1].ActionRecord.ActionID)
		if err != nil {
			t.Fatalf("ReceiptDetail: %v", err)
		}
		if !found {
			t.Fatal("expected receipt to be found")
		}
		if !exp.Verdict.Present {
			t.Fatal("Verdict should be present")
		}
		if exp.Verdict.Detail != "allow" {
			t.Fatalf("Verdict.Detail = %q, want allow", exp.Verdict.Detail)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		_, found, err := model.ReceiptDetail(testSessionID, "missing-action-id")
		if err != nil {
			t.Fatalf("ReceiptDetail: %v", err)
		}
		if found {
			t.Fatal("expected receipt to not be found")
		}
	})

	t.Run("not_found_in_truncated_view", func(t *testing.T) {
		limited := NewReadModel(Options{ReceiptDir: dir, ReceiptReadLimit: 1})
		_, found, err := limited.ReceiptDetail(testSessionID, "missing-action-id")
		if found || !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
			t.Fatalf("ReceiptDetail truncated result = found %v, err %v", found, err)
		}
	})

	t.Run("independent_chains_with_same_seq_select_by_action_id", func(t *testing.T) {
		collisionDir := t.TempDir()
		first := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC))
		second := signDashboardReceipt(t, priv, 0, receipt.GenesisHash, time.Date(2026, 7, 3, 12, 1, 0, 0, time.UTC))
		second.ActionRecord.Verdict = "block"
		var err error
		second, err = receipt.Sign(second.ActionRecord, priv)
		if err != nil {
			t.Fatalf("Sign(second): %v", err)
		}
		writeReceiptsToDir(t, collisionDir, []receipt.Receipt{first, second})

		collisionModel := NewReadModel(Options{ReceiptDir: collisionDir})
		exp, found, err := collisionModel.ReceiptDetail(testSessionID, second.ActionRecord.ActionID)
		if err != nil {
			t.Fatalf("ReceiptDetail: %v", err)
		}
		if !found {
			t.Fatal("expected second chain receipt to be found")
		}
		if exp.Verdict.Detail != "block" {
			t.Fatalf("Verdict.Detail = %q, want block from second independent chain", exp.Verdict.Detail)
		}
	})
}

// --- RedactExplanation strips Target in metadata view ---

func TestRedactExplanation_StripsTarget(t *testing.T) {
	t.Parallel()

	exp := evidenceview.DecisionExplanation{
		Target: evidenceview.ExplanationField{
			Present: true,
			Label:   "Target",
			Detail:  "https://api.vendor.example/secret",
		},
		TaintSourcesRawLen: 3,
	}
	redacted := evidenceview.RedactExplanation(exp)
	if redacted.Target.Detail != evidenceview.RedactedDestination {
		t.Fatalf("Target.Detail = %q, want redaction placeholder", redacted.Target.Detail)
	}
	if redacted.TaintSourcesRawLen != 0 {
		t.Fatalf("TaintSourcesRawLen = %d, want 0 after redaction", redacted.TaintSourcesRawLen)
	}
}

// --- Session receipt sub-route preserves existing session path behavior ---

func TestHandler_SessionPathStillWorks(t *testing.T) {
	t.Parallel()

	dir, trusted := writeTrustedHandlerSession(t)
	handler := New(Options{
		TrustedOuterAuth: true, TrustedOuterAuthBoundary: "test-fixture: fake outer auth boundary",
		ReceiptDir:  dir,
		TrustedKeys: trusted,
		HasFeature:  allowAgentsFeature,
	})

	t.Run("direct_session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/"+testSessionID, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "Scorecard") {
			t.Fatal("session view should render scorecard")
		}
	})

	t.Run("empty_session", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequestWithContext(
			context.Background(), http.MethodGet, "/session/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("empty session status = %d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}

func TestApplyFilter_VerdictSelects(t *testing.T) {
	sessions := []SessionSummary{
		{ID: "s1", Agent: "agent-a", Verdicts: []string{"allow", "block"}},
		{ID: "s2", Agent: "agent-b", Verdicts: []string{"allow"}},
		{ID: "s3", Agent: "agent-c", Verdicts: nil},
	}

	cases := []struct {
		name    string
		filter  FilterSpec
		wantIDs []string
	}{
		{"no verdict filter returns all", FilterSpec{}, []string{"s1", "s2", "s3"}},
		{"block selects only blocking session", FilterSpec{Verdict: verdictBlock}, []string{"s1"}},
		{"allow selects both allowing sessions", FilterSpec{Verdict: verdictAllow}, []string{"s1", "s2"}},
		{"warn selects none", FilterSpec{Verdict: verdictWarn}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFilter(sessions, normalizeFilter(tc.filter))
			gotIDs := make([]string, 0, len(got))
			for _, s := range got {
				gotIDs = append(gotIDs, s.ID)
			}
			if len(gotIDs) != len(tc.wantIDs) {
				t.Fatalf("filter %+v selected %v, want %v", tc.filter, gotIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if gotIDs[i] != tc.wantIDs[i] {
					t.Fatalf("filter %+v selected %v, want %v", tc.filter, gotIDs, tc.wantIDs)
				}
			}
		})
	}
}

func TestApplyFilter_AgentSubstringCaseInsensitive(t *testing.T) {
	sessions := []SessionSummary{
		{ID: "s1", Agent: "prod-web-agent"},
		{ID: "s2", Agent: "prod-worker"},
		{ID: "s3", Agent: "staging-web"},
	}
	cases := []struct {
		name    string
		agent   string
		wantIDs []string
	}{
		{"substring matches multiple", "prod", []string{"s1", "s2"}},
		{"case-insensitive", "WEB", []string{"s1", "s3"}},
		{"exact still matches", "prod-worker", []string{"s2"}},
		{"no match", "nope", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := applyFilter(sessions, normalizeFilter(FilterSpec{Agent: tc.agent}))
			gotIDs := make([]string, 0, len(got))
			for _, s := range got {
				gotIDs = append(gotIDs, s.ID)
			}
			if len(gotIDs) != len(tc.wantIDs) {
				t.Fatalf("agent %q selected %v, want %v", tc.agent, gotIDs, tc.wantIDs)
			}
			for i := range tc.wantIDs {
				if gotIDs[i] != tc.wantIDs[i] {
					t.Fatalf("agent %q selected %v, want %v", tc.agent, gotIDs, tc.wantIDs)
				}
			}
		})
	}
}

func TestReadModel_ReceiptDetailPrefersTerminalPhase(t *testing.T) {
	t.Parallel()

	_, priv := generateDashboardKey(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	signPair := func(t *testing.T, first, second string, secondVerdict string) []receipt.Receipt {
		t.Helper()
		ar := validDashboardAction(0, receipt.GenesisHash, base)
		ar.DecisionPhase = first
		head, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign(head): %v", err)
		}
		prev, err := receipt.ReceiptHash(head)
		if err != nil {
			t.Fatalf("ReceiptHash: %v", err)
		}
		ar.ChainSeq, ar.ChainPrevHash, ar.Timestamp = 1, prev, base.Add(time.Second)
		ar.DecisionPhase, ar.Verdict, ar.Layer = second, secondVerdict, "outcome"
		ar.Pattern = "status=200 bytes=16 reason=delivery_error delivered_bytes=7"
		tail, err := receipt.Sign(ar, priv)
		if err != nil {
			t.Fatalf("Sign(tail): %v", err)
		}
		return []receipt.Receipt{head, tail}
	}

	for _, tc := range []struct {
		name          string
		first, second string
		reversed      bool
	}{
		{name: "outcome_after_intent", first: receipt.DecisionPhaseIntent, second: receipt.DecisionPhaseOutcome},
		{name: "resolution_after_defer", first: receipt.DecisionPhaseDefer, second: receipt.DecisionPhaseResolution},
		{name: "outcome_recorded_before_intent", first: receipt.DecisionPhaseIntent, second: receipt.DecisionPhaseOutcome, reversed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			pair := signPair(t, tc.first, tc.second, "warn")
			if tc.reversed {
				pair[0], pair[1] = pair[1], pair[0]
			}
			writeReceiptsToDir(t, dir, pair)
			exp, found, err := NewReadModel(Options{ReceiptDir: dir}).ReceiptDetail(testSessionID, pair[0].ActionRecord.ActionID)
			if err != nil || !found {
				t.Fatalf("ReceiptDetail: found=%v err=%v", found, err)
			}
			if exp.DecisionPhase.Detail != tc.second || exp.Verdict.Detail != "warn" {
				t.Fatalf("selected phase=%q verdict=%q, want %s/warn", exp.DecisionPhase.Detail, exp.Verdict.Detail, tc.second)
			}
		})
	}

	t.Run("intent_only_is_shown", func(t *testing.T) {
		dir := t.TempDir()
		pair := signPair(t, receipt.DecisionPhaseIntent, receipt.DecisionPhaseOutcome, "warn")
		writeReceiptsToDir(t, dir, pair[:1])
		exp, found, err := NewReadModel(Options{ReceiptDir: dir}).ReceiptDetail(testSessionID, pair[0].ActionRecord.ActionID)
		if err != nil || !found || exp.DecisionPhase.Detail != receipt.DecisionPhaseIntent {
			t.Fatalf("intent-only lookup: phase=%q found=%v err=%v", exp.DecisionPhase.Detail, found, err)
		}
	})

	t.Run("truncated_view_does_not_present_intent_as_final", func(t *testing.T) {
		dir := t.TempDir()
		pair := signPair(t, receipt.DecisionPhaseIntent, receipt.DecisionPhaseOutcome, "warn")
		writeReceiptsToDir(t, dir, pair)
		_, found, err := NewReadModel(Options{ReceiptDir: dir, ReceiptReadLimit: 1}).ReceiptDetail(testSessionID, pair[0].ActionRecord.ActionID)
		if found || !errors.Is(err, recorder.ErrEvidenceReadLimitExceeded) {
			t.Fatalf("truncated intent lookup: found=%v err=%v", found, err)
		}
	})

	type step struct{ phase, verdict, layer, pattern string }
	signSteps := func(t *testing.T, steps []step) []receipt.Receipt {
		t.Helper()
		var chain []receipt.Receipt
		prev := receipt.GenesisHash
		actionID := receipt.NewActionID()
		for i, st := range steps {
			ar := validDashboardAction(uint64(i), prev, base.Add(time.Duration(i)*time.Second))
			ar.ActionID = actionID
			ar.DecisionPhase, ar.Verdict, ar.Layer, ar.Pattern = st.phase, st.verdict, st.layer, st.pattern
			r, err := receipt.Sign(ar, priv)
			if err != nil {
				t.Fatal(err)
			}
			if prev, err = receipt.ReceiptHash(r); err != nil {
				t.Fatal(err)
			}
			chain = append(chain, r)
		}
		return chain
	}
	for _, tc := range []struct {
		name        string
		steps       []step
		wantPhase   string
		wantVerdict string
	}{
		{
			name: "allow_outcome_does_not_hide_warn_finding",
			steps: []step{
				{receipt.DecisionPhaseIntent, "warn", "dlp_header", "header finding"},
				{receipt.DecisionPhaseOutcome, "allow", "outcome", "status=200 bytes=16 reason=complete"},
			},
			wantPhase: receipt.DecisionPhaseIntent, wantVerdict: "warn",
		},
		{
			name: "allow_outcome_does_not_hide_block_record",
			steps: []step{
				{receipt.DecisionPhaseIntent, "allow", "allowlist", "api.vendor.example"},
				{"", "block", "response_scan", "response finding"},
				{receipt.DecisionPhaseOutcome, "allow", "outcome", "status=403 bytes=0 reason=response_incomplete"},
			},
			wantPhase: "", wantVerdict: "block",
		},
		{
			name: "warn_outcome_does_not_hide_warn_finding",
			steps: []step{
				{receipt.DecisionPhaseIntent, "warn", "dlp_header", "header finding"},
				{receipt.DecisionPhaseOutcome, "warn", "outcome", "status=200 bytes=16 reason=delivery_error delivered_bytes=7"},
			},
			wantPhase: receipt.DecisionPhaseIntent, wantVerdict: "warn",
		},
		{
			name: "allow_resolution_replaces_defer",
			steps: []step{
				{receipt.DecisionPhaseDefer, "defer", "approval", "awaiting approval"},
				{receipt.DecisionPhaseResolution, "allow", "approval", "approved"},
			},
			wantPhase: receipt.DecisionPhaseResolution, wantVerdict: "allow",
		},
	} {
		for _, reversed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/reversed=%t", tc.name, reversed), func(t *testing.T) {
				dir := t.TempDir()
				chain := signSteps(t, tc.steps)
				if reversed {
					chain[0], chain[1] = chain[1], chain[0]
				}
				writeReceiptsToDir(t, dir, chain)
				exp, found, err := NewReadModel(Options{ReceiptDir: dir}).ReceiptDetail(testSessionID, chain[0].ActionRecord.ActionID)
				if err != nil || !found {
					t.Fatalf("ReceiptDetail: found=%v err=%v", found, err)
				}
				// A phase-less record has no phase to compare.
				if (tc.wantPhase != "" && exp.DecisionPhase.Detail != tc.wantPhase) || exp.Verdict.Detail != tc.wantVerdict {
					t.Fatalf("selected %s/%s, want %s/%s", exp.DecisionPhase.Detail, exp.Verdict.Detail, tc.wantPhase, tc.wantVerdict)
				}
			})
		}
	}

	t.Run("truncated_view_still_shows_legacy_record", func(t *testing.T) {
		dir := t.TempDir()
		legacy := buildDashboardChain(t, priv, 2)
		writeReceiptsToDir(t, dir, legacy)
		exp, found, err := NewReadModel(Options{ReceiptDir: dir, ReceiptReadLimit: 1}).ReceiptDetail(testSessionID, legacy[0].ActionRecord.ActionID)
		if err != nil || !found || exp.Verdict.Detail != "allow" {
			t.Fatalf("truncated legacy lookup: verdict=%q found=%v err=%v", exp.Verdict.Detail, found, err)
		}
	})
}
