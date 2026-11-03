// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// An intercepted stream keeps its handler open until the upstream ends. The
// URL decision must already be counted while the stream is still running.
func TestURLDecisionInterceptCountedDuringStream(t *testing.T) {
	cache, pool, cfg, sc, logger, m := testInterceptSetup(t)
	body, upstream := io.Pipe()
	// Close the upstream before the helper's cleanups run: they close the
	// client side, which waits for the stream to end.
	defer func() { _ = upstream.Close() }()
	rt := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{headerContentType: []string{"text/event-stream"}},
			Body:       body,
		}, nil
	})
	go func() { _, _ = upstream.Write([]byte("data: first\n\n")) }()

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		"https://"+net.JoinHostPort(testLoopbackIP, "9999")+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	type read struct {
		line string
		err  error
	}
	got := make(chan read, 1)
	go func() {
		resp, err := interceptWithRTResult(t, cache, pool, cfg, sc, logger, m, rt,
			&InterceptContext{TargetHost: testLoopbackIP, TargetPort: "9999"}, req)
		if err != nil {
			got <- read{err: err}
			return
		}
		defer func() { _ = resp.Body.Close() }()
		line, err := bufio.NewReader(resp.Body).ReadString('\n')
		got <- read{line: line, err: err}
	}()
	select {
	case r := <-got:
		if r.err != nil || r.line != "data: first\n" {
			t.Fatalf("first event = %q, err %v", r.line, r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("first event did not arrive while the stream was open")
	}
	// The upstream stream is still open here.
	assertMetricSampleValue(t, m, `pipelock_url_check_decisions_total{check="entropy",outcome="allowed",part="url",transport="intercept"}`, 1)
}
