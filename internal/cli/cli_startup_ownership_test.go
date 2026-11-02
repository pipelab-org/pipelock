// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testport"
	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

type cliStartupRoundTripper func(*http.Request) (*http.Response, error)

func (f cliStartupRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestRunHTTPWaitRequiresOwnedStartup(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const healthURL = "http://proxy.vendor.example/health"
		stderr := &cliTestBuffer{}
		errCh := make(chan error, 1)
		var requests atomic.Int32
		client := &http.Client{Transport: cliStartupRoundTripper(func(req *http.Request) (*http.Response, error) {
			requests.Add(1)
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		})}
		done := make(chan error, 1)
		go func() {
			done <- waitForRunHTTPResult(t.Context(), client, cliTestRun{stderr: stderr, errCh: errCh, healthURL: healthURL}, healthURL, func(resp *http.Response) bool {
				return resp.StatusCode == http.StatusOK
			}, "owned health")
		}()

		_, _ = fmt.Fprint(stderr, "Pipelock starting\n  Health: http://other.vendor.example/health\n")
		// Use the same fake-clock poll ordering as the reload startup test.
		<-time.After(50 * time.Millisecond)
		synctest.Wait()
		if got := requests.Load(); got != 0 {
			t.Fatalf("contacted a listener before this command's post-bind banner: %d requests", got)
		}
		select {
		case err := <-done:
			t.Fatalf("health wait returned before the owned startup banner: %v", err)
		default:
		}

		_, _ = fmt.Fprintf(stderr, "  Health: %s\n", healthURL)
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(testwait.Deadline(5 * time.Second)):
			t.Fatal("health wait did not finish after the owned startup banner")
		}
		if got := requests.Load(); got != 1 {
			t.Fatalf("requests after the owned startup banner = %d, want 1", got)
		}
	})
}

func TestRunCmd_HealthBindCollisionRetries(t *testing.T) {
	attempts := 0
	collided := false
	testport.WithRetry(t, 1, func(addrs []string) error {
		attempts++
		addr := addrs[0]
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		client := &http.Client{Timeout: time.Second}
		healthURL := "http://" + addr + "/health"
		collide := !collided
		if collide {
			ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", addr)
			if err != nil {
				return err
			}
			foreign := &http.Server{
				Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusOK)
				}),
				ReadHeaderTimeout: time.Second,
			}
			go func() { _ = foreign.Serve(ln) }()
			defer func() { _ = foreign.Close() }()
			// Pin the misleading response before starting the real command.
			if err := waitForRunHTTPWithinResult(5*time.Second, ctx, client, make(chan error), healthURL, func(resp *http.Response) bool {
				return resp.StatusCode == http.StatusOK
			}, "foreign health before command startup"); err != nil {
				return err
			}
			collided = true
		}

		cfgPath := filepath.Join(t.TempDir(), "test.yaml")
		cfg := fmt.Sprintf("version: 1\nmode: balanced\nfetch_proxy:\n  listen: %q\nforward_proxy:\n  enabled: true\n", addr)
		if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
			t.Fatal(err)
		}
		stderr := &cliTestBuffer{}
		cmd := rootCmd()
		cmd.SetContext(ctx)
		cmd.SetArgs([]string{"run", "--config", cfgPath})
		cmd.SetOut(stderr)
		cmd.SetErr(stderr)
		errCh := make(chan error, 1)
		go func() { errCh <- cmd.Execute() }()
		err := waitForRunHTTPResult(ctx, client, cliTestRun{stderr: stderr, errCh: errCh, healthURL: healthURL}, healthURL, func(resp *http.Response) bool {
			var health map[string]any
			_ = json.NewDecoder(resp.Body).Decode(&health)
			return resp.StatusCode == http.StatusOK && health["forward_proxy_enabled"] == true
		}, "owned forward proxy health")
		if err != nil {
			return err
		}
		if collide {
			return errors.New("accepted foreign health without reporting the command's bind collision")
		}
		cancel()
		select {
		case err := <-errCh:
			return err
		case <-time.After(testwait.Deadline(10 * time.Second)):
			return errors.New("run did not shut down")
		}
	})
	if !collided || attempts < 2 {
		t.Fatalf("forced collision = %v, attempts = %d; want a collision and successful retry", collided, attempts)
	}
}
