// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/httpstream"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestHandlerDrainParity(t *testing.T) {
	for _, pending := range []bool{true, false} {
		t.Run(fmt.Sprintf("pending=%t", pending), func(t *testing.T) {
			h := newTestHandler(t)
			h.cfg.DLP.Patterns = append(h.cfg.DLP.Patterns, config.DLPPattern{Name: "drain-warning-probe", Regex: "drain-warning-probe", Severity: config.SeverityLow, Action: config.ActionWarn})
			h.scanner = scanner.MustNew(h.cfg)
			defer h.scanner.Close()
			entered, release, finished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			h.scanner.SetDLPWarnHook(func(context.Context, string, string) { close(entered); <-release })
			gate := &httpstream.Gate{}
			srv := httptest.NewUnstartedServer(gate.Wrap(h))
			srv.Config.ReadHeaderTimeout = time.Second
			srv.Start()
			defer srv.Close()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/api/v1/scan", strings.NewReader(`{"kind":"dlp","input":{"text":"drain-warning-probe"}}`))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Authorization", "Bearer "+testToken)
			req.Header.Set("Content-Type", "application/json")
			go func() {
				defer close(finished)
				resp, requestErr := srv.Client().Do(req)
				if requestErr == nil {
					_, _ = io.Copy(io.Discard, resp.Body)
					_ = resp.Body.Close()
				}
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("Scan API warning hook did not run")
			}
			if !pending {
				close(release)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
			defer cancel()
			err = httpstream.DrainServer(ctx, httpstream.GatedServer{Server: srv.Config, Gate: gate})
			if pending && !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("held scan drain = %v, want deadline", err)
			}
			if !pending && err != nil {
				t.Errorf("finished scan drain = %v", err)
			}
			if pending {
				close(release)
			}
			select {
			case <-finished:
			case <-time.After(5 * time.Second):
				t.Fatal("scan request did not stop")
			}
			joined, joinCancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer joinCancel()
			if err := httpstream.DrainServer(joined, httpstream.GatedServer{Server: srv.Config, Gate: gate}); err != nil {
				t.Error(err)
			}
		})
	}
}
