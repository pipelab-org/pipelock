// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestAwaitProxyLongerTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	port, err := freePort(ctx)
	if err != nil {
		t.Fatal(err)
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	p := &proxyProc{exited: make(chan struct{})}
	longDone := make(chan error, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		longDone <- awaitProxy(ctx, addr, p, 4*time.Second)
	}()
	t.Cleanup(func() { cancel(); <-joined })

	// Keep the listener closed until the shorter readiness budget expires.
	if err := awaitProxy(ctx, addr, p, 200*time.Millisecond); err == nil || !strings.Contains(err.Error(), "proxy did not listen") {
		t.Fatalf("short readiness wait = %v, want timeout", err)
	}
	select {
	case err := <-longDone:
		t.Fatalf("long readiness wait ended before listening: %v", err)
	default:
	}
	l, err := (&net.ListenConfig{}).Listen(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	select {
	case err := <-longDone:
		if err != nil {
			t.Fatalf("long readiness wait = %v", err)
		}
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestAwaitProxyExitBeforeListen(t *testing.T) {
	for _, exitErr := range []error{nil, errors.New("startup failed")} {
		t.Run(strconv.FormatBool(exitErr != nil), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			port, err := freePort(ctx)
			if err != nil {
				t.Fatal(err)
			}
			p := &proxyProc{exited: make(chan struct{}), exitErr: exitErr}
			close(p.exited)
			err = awaitProxy(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), p, time.Minute)
			if err == nil || !strings.Contains(err.Error(), "proxy exited before listening") || (exitErr != nil && !errors.Is(err, exitErr)) {
				t.Fatalf("readiness wait = %v, want immediate process exit (%v)", err, exitErr)
			}
		})
	}
}

func TestAwaitProxyCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := awaitProxy(ctx, "127.0.0.1:0", &proxyProc{exited: make(chan struct{})}, time.Minute)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("readiness wait = %v, want cancellation", err)
	}
}
