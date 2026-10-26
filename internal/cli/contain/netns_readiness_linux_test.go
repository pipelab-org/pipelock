// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testwait"
)

func forwarderNotifySocket(t *testing.T) *net.UnixConn {
	t.Helper()
	dir, err := os.MkdirTemp("", "plk-ready-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "notify.sock")
	ln, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram", Name: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	if err := ln.SetReadDeadline(time.Now().Add(testwait.Deadline(5 * time.Second))); err != nil {
		t.Fatal(err)
	}
	return ln
}

func TestNetnsForwardReportsReadyAfterBind(t *testing.T) {
	notify := forwarderNotifySocket(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runNetnsForward(ctx, netnsForwardOpts{listen: "127.0.0.1:0", targetTCP: "127.0.0.1:1"}, io.Discard)
	}()
	buf := make([]byte, 128)
	n, _, err := notify.ReadFromUnix(buf)
	cancel()
	if err != nil {
		t.Fatalf("receive readiness: %v", err)
	}
	if string(buf[:n]) != "READY=1" {
		t.Fatalf("notification = %q", buf[:n])
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(testwait.Deadline(5 * time.Second)):
		t.Fatal("forwarder did not stop")
	}
}

func TestNetnsForwardBindFailureDoesNotReportReady(t *testing.T) {
	notify := forwarderNotifySocket(t)
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	err = runNetnsForward(t.Context(), netnsForwardOpts{listen: ln.Addr().String(), targetTCP: "127.0.0.1:1"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), ln.Addr().String()) {
		t.Fatalf("bind error = %v", err)
	}
	if err := notify.SetReadDeadline(time.Now().Add(testwait.Deadline(time.Second))); err != nil {
		t.Fatal(err)
	}
	_, _, err = notify.ReadFromUnix(make([]byte, 128))
	if err == nil {
		t.Fatal("reported readiness for an occupied listener")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read notification = %v", err)
	}
}

func TestNetnsForwardNotifyFailureStopsStartup(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
	ctx, cancel := context.WithTimeout(t.Context(), testwait.Deadline(time.Second))
	defer cancel()
	err := runNetnsForward(ctx, netnsForwardOpts{listen: "127.0.0.1:0", targetTCP: "127.0.0.1:1"}, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "report listener readiness") {
		t.Fatalf("startup error = %v", err)
	}
}
