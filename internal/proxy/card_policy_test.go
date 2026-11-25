// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/metrics"

	"github.com/luckyPipewrench/pipelock/internal/cardtest"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestCardBarePolicyBody(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		cfg := testScannerConfig()
		cfg.DLP.CardBareAction = action
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		for _, tc := range []struct {
			text  string
			block bool
		}{
			{`{"value":"` + pan + `"}`, action == config.ActionBlock},
			{`{"card":"` + pan + `"}`, true},
			{`{"card":"` + pan[:4] + `\t` + pan[4:] + `"}`, true},
			{`{"card":"` + pan[:4] + `.` + pan[4:] + `"}`, true},
			{`{"value":"F27=` + pan[:4] + `.` + pan[4:] + `"}`, false},
		} {
			_, r := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(tc.text), ContentType: contentTypeJSON, MaxBytes: 1 << 20, Scanner: sc, Action: config.ActionBlock, Host: "api.vendor.example"})
			if got := !r.Clean && r.Action == config.ActionBlock; got != tc.block {
				t.Fatalf("action %s input %q got %+v", action, tc.text, r)
			}
		}
	}
}

func TestCardBarePolicyFetchURL(t *testing.T) {
	pan := cardtest.Issuer("4019", 16)
	for _, action := range []string{config.ActionBlock, config.ActionWarn} {
		cfg := testScannerConfig()
		cfg.DLP.CardBareAction = action
		sc := scanner.MustNew(cfg)
		t.Cleanup(sc.Close)
		p, err := New(cfg, audit.NewNop(), sc, metrics.New())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(p.Close)
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/fetch?url=https://api.vendor.example/"+pan, nil)
		w := httptest.NewRecorder()
		p.handleFetch(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s URL status=%d", action, w.Code)
		}
	}
}
