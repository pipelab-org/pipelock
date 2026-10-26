// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package sdnotify

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSend(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", "")
		if sent, err := Send("READY=1"); sent || err != nil {
			t.Fatalf("Send = %t, %v", sent, err)
		}
	})
	t.Run("missing socket", func(t *testing.T) {
		t.Setenv("NOTIFY_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))
		if sent, err := Send("READY=1"); sent || err == nil || !strings.Contains(err.Error(), "dial NOTIFY_SOCKET") {
			t.Fatalf("Send = %t, %v", sent, err)
		}
	})
	for _, abstract := range []bool{false, true} {
		name := "pathname"
		if abstract {
			name = "abstract"
		}
		t.Run(name, func(t *testing.T) {
			dir, err := os.MkdirTemp("", "plk-notify-")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.RemoveAll(dir) }()
			address := filepath.Join(dir, "notify.sock")
			if abstract {
				address = "@" + address
			}
			listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Net: "unixgram", Name: address})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = listener.Close() }()
			t.Setenv("NOTIFY_SOCKET", address)
			if sent, err := Send("READY=1"); !sent || err != nil {
				t.Fatalf("Send = %t, %v", sent, err)
			}
			if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 128)
			n, _, err := listener.ReadFromUnix(buf)
			if err != nil || string(buf[:n]) != "READY=1" {
				t.Fatalf("datagram = %q, %v", buf[:n], err)
			}
		})
	}
}
