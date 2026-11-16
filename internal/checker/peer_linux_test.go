// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package checker

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestPeerUID(t *testing.T) {
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "checker.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	parsed, err := strconv.ParseUint(strconv.Itoa(os.Getuid()), 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	uid := uint32(parsed)
	for _, tc := range []struct {
		name    string
		uid     uint32
		wantErr bool
	}{{"same", uid, false}, {"different", uid ^ 1, true}} {
		t.Run(tc.name, func(t *testing.T) {
			if err := PeerUID(tc.uid)(conn); (err != nil) != tc.wantErr {
				t.Fatalf("peer check: %v", err)
			}
		})
	}
	a, b := net.Pipe()
	defer func() { _ = a.Close(); _ = b.Close() }()
	if err := PeerUID(uid)(a); err == nil {
		t.Fatal("non-Unix connection accepted")
	}
}
