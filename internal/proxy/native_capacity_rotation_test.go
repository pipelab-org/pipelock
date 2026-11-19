// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"cmp"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receipt"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/signing"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func TestReceiptRotationWaitsForAdmittedFetch(t *testing.T) {
	t.Run("outcome still pending", func(t *testing.T) { testReceiptRotationWaitsForAdmittedFetch(t, false) })
	t.Run("outcome recorded during rotation staging", func(t *testing.T) { testReceiptRotationWaitsForAdmittedFetch(t, true) })
}

func testReceiptRotationWaitsForAdmittedFetch(t *testing.T, completesDuringStaging bool) {
	t.Helper()
	p, old, dir := newNativeCapacityProxy(t, nativeRequestRecords+4)
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(3*time.Second))
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	finish := sync.OnceFunc(func() { close(release) })
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(entered)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		if _, err := io.WriteString(w, "fixture fetch completed"); err != nil {
			t.Error(err)
		}
	}))
	defer upstream.Close()
	defer finish()
	_, port, err := net.SplitHostPort(upstream.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	dst := "http://api.vendor.example:" + port + "/"
	response := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		defer close(done)
		p.handleFetch(response, httptest.NewRequestWithContext(ctx, http.MethodGet, "/fetch?url="+url.QueryEscape(dst), nil))
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("admitted fetch did not reach upstream")
	}
	cfg := p.CurrentConfig().Clone()
	_, newKey, err := signing.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	cfg.FlightRecorder.SigningKeyPath = filepath.Join(t.TempDir(), "receipt.key")
	if err := signing.SavePrivateKey(newKey, cfg.FlightRecorder.SigningKeyPath); err != nil {
		t.Fatal(err)
	}
	reload := func() bool {
		sc, err := scanner.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return p.Reload(cfg, sc)
	}
	if completesDuringStaging {
		p.reloadLocked = func() {
			finish()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("admitted fetch did not settle during staging")
			}
		}
	}
	if reload() || p.receiptEmitterPtr.Load() != old {
		t.Error("signer rotation published a stale receipt head")
	}
	p.reloadLocked = nil
	finish()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("admitted fetch did not complete")
	}
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "fixture fetch completed") {
		t.Errorf("fetch response = %d %q", response.Code, response.Body.String())
	}
	if !reload() || p.receiptEmitterPtr.Load() == old {
		t.Fatal("signer rotation was not applied once the admitted fetch settled")
	}
	replacement := p.receiptEmitterPtr.Load()
	verifyReceiptRotation(t, dir, old, replacement)
}

func verifyReceiptRotation(t *testing.T, dir string, old, replacement *receipt.Emitter) {
	t.Helper()
	result, err := recorder.QuerySession(dir, old.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(result.Entries, func(a, b recorder.Entry) int {
		return cmp.Compare(a.Sequence, b.Sequence)
	})
	var receipts []receipt.Receipt
	var sawOutcome bool
	for _, entry := range result.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		receipts = append(receipts, signed)
		if signed.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome &&
			strings.Contains(signed.ActionRecord.Pattern, "reason=complete") {
			if err := receipt.VerifyWithKey(signed, old.SignerKeyHex()); err != nil {
				t.Fatal(err)
			}
			sawOutcome = true
		}
	}
	if !sawOutcome {
		t.Fatal("admitting emitter recorded no completed fetch outcome")
	}
	keys := []string{old.SignerKeyHex(), replacement.SignerKeyHex()}
	if res := receipt.VerifyChainIntegrityTrusted(receipts, keys); !res.Valid {
		t.Fatalf("receipt chain after rotation: %s", res.Error)
	}
}
