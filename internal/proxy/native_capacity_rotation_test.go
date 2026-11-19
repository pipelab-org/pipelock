// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
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
	if reload() || p.receiptEmitterPtr.Load() != old {
		t.Error("signer rotation published while fetch still held its outcome reservation")
	}
	finish()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("admitted fetch did not complete")
	}
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "fixture fetch completed") {
		t.Errorf("fetch response = %d %q", response.Code, response.Body.String())
	}
	verifyCompletedFetchReceipt(t, old, dir)
	if !reload() || p.receiptEmitterPtr.Load() == old {
		t.Fatal("signer rotation was not applied once the admitted fetch settled")
	}
}

func verifyCompletedFetchReceipt(t *testing.T, emitter *receipt.Emitter, dir string) {
	t.Helper()
	result, err := recorder.QuerySession(dir, emitter.Session(), &recorder.QueryFilter{Type: "action_receipt"})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range result.Entries {
		signed, err := receipt.Unmarshal(entry.RawDetail)
		if err != nil {
			t.Fatal(err)
		}
		if signed.ActionRecord.DecisionPhase == receipt.DecisionPhaseOutcome &&
			strings.Contains(signed.ActionRecord.Pattern, "reason=complete") {
			if err := receipt.VerifyWithKey(signed, emitter.SignerKeyHex()); err != nil {
				t.Fatal(err)
			}
			return
		}
	}
	t.Fatal("admitting emitter recorded no completed fetch outcome")
}
