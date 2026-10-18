// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestMetadataSafeDialContext_BlocksMetadataAtDialTime(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"metadata.vendor.example": {"169.254.169.254"},
		"mapped.vendor.example":   {"::ffff:169.254.169.254"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	dial := NewMetadataSafeDialContext(func() *scanner.Scanner { return sc })

	tests := []struct {
		name string
		addr string
	}{
		{name: "literal IPv4 metadata", addr: "169.254.169.254:80"},
		{name: "DNS metadata", addr: "metadata.vendor.example:80"},
		{name: "IPv4-mapped DNS metadata", addr: "mapped.vendor.example:80"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := dial(context.Background(), "tcp", tt.addr)
			if err == nil {
				t.Fatal("expected metadata dial to fail closed")
			}
			if !strings.Contains(err.Error(), "ssrf_metadata") {
				t.Fatalf("dial error = %v, want ssrf_metadata classification", err)
			}
		})
	}
}

func TestMetadataSafeDialContext_BlocksMetadataHostnameWithoutScanner(t *testing.T) {
	origLookup := defaultMCPDialLookupHost
	defaultMCPDialLookupHost = func(context.Context, string) ([]string, error) {
		return []string{"169.254.169.254"}, nil
	}
	t.Cleanup(func() { defaultMCPDialLookupHost = origLookup })

	dial := NewMetadataSafeDialContext(nil)
	_, err := dial(context.Background(), "tcp", "metadata.vendor.example:80")
	if err == nil {
		t.Fatal("expected metadata hostname dial to fail closed without scanner")
	}
	if !strings.Contains(err.Error(), "ssrf_metadata") {
		t.Fatalf("dial error = %v, want ssrf_metadata classification", err)
	}
}

func TestMetadataSafeDialContext_AllowsNonMetadataLoopbackUpstream(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"local.vendor.example": {"127.0.0.1"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listener addr: %v", err)
	}
	dial := NewMetadataSafeDialContext(func() *scanner.Scanner { return sc })

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dial(ctx, "tcp", net.JoinHostPort("local.vendor.example", port))
	if err != nil {
		t.Fatalf("loopback MCP upstream should remain allowed: %v", err)
	}
	_ = conn.Close()
	select {
	case acceptedConn := <-accepted:
		_ = acceptedConn.Close()
	case <-ctx.Done():
		t.Fatal("listener did not receive loopback dial")
	}
}

func TestMetadataSafeDialContext_AllowsNonMetadataPrivateUpstream(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"private.vendor.example": {"10.0.0.8"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)

	var dialedAddr string
	dial := newMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(_ context.Context, _ string, addr string) (net.Conn, error) {
		dialedAddr = addr
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	})

	conn, err := dial(context.Background(), "tcp", "private.vendor.example:443")
	if err != nil {
		t.Fatalf("private non-metadata MCP upstream should remain allowed: %v", err)
	}
	_ = conn.Close()
	if dialedAddr != "10.0.0.8:443" {
		t.Fatalf("dialed addr = %q, want %q", dialedAddr, "10.0.0.8:443")
	}
}

func TestMetadataSafeDialContext_BlocksEmbeddedAndDirectMetadata(t *testing.T) {
	literals := []string{
		"[64:ff9b::a9fe:a9fe]:80",
		"[64:ff9b::a83f:8110]:80",
		"[64:ff9b::6464:64c8]:80",
		"[2002:a9fe:a9fe::]:80",
		"[::169.254.169.254]:80",
		"[2001:0:a9fe:a9fe::]:80",
		"[2001::5601:5601]:80",
		"[fd00:ec2::254]:80",
		"[fd00:ec2::254%eth0]:80",
		"[::ffff:169.254.169.254]:80",
		"169.254.169.254:80",
		"168.63.129.16:80",
		"100.100.100.200:80",
	}
	for _, tc := range []struct {
		name    string
		scanner bool
	}{
		{name: "scanner configured", scanner: true},
		{name: "scannerless"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sc *scanner.Scanner
			var scannerFn func() *scanner.Scanner
			if tc.scanner {
				cfg := config.Defaults()
				cfg.Internal = nil
				sc = scanner.MustNew(cfg)
				t.Cleanup(sc.Close)
				scannerFn = func() *scanner.Scanner { return sc }
			}
			dial := newMetadataSafeDialContext(scannerFn, func(context.Context, string, string) (net.Conn, error) {
				t.Fatal("metadata address was dialed")
				return nil, nil
			})
			for _, addr := range literals {
				_, err := dial(context.Background(), "tcp", addr)
				assertMetadataDialBlock(t, err)
			}
		})
	}

	cfg := config.Defaults()
	cfg.DNS.HostOverrides = map[string][]string{
		"wkp.vendor.example":    {"64:ff9b::a9fe:a9fe"},
		"azure.vendor.example":  {"64:ff9b::a83f:8110"},
		"ali.vendor.example":    {"64:ff9b::6464:64c8"},
		"v6.vendor.example":     {"fd00:ec2::254"},
		"mixed.vendor.example":  {"8.8.8.8", "64:ff9b::a9fe:a9fe"},
		"mapped.vendor.example": {"::ffff:168.63.129.16"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	dialed := false
	dial := newMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, nil
	})
	for _, host := range []string{"wkp.vendor.example", "azure.vendor.example", "ali.vendor.example", "v6.vendor.example", "mixed.vendor.example", "mapped.vendor.example"} {
		dialed = false
		_, err := dial(context.Background(), "tcp", net.JoinHostPort(host, "80"))
		assertMetadataDialBlock(t, err)
		if dialed {
			t.Errorf("%s dialed despite a metadata answer", host)
		}
	}

	origLookup := defaultMCPDialLookupHost
	defaultMCPDialLookupHost = func(context.Context, string) ([]string, error) {
		return []string{"8.8.8.8", "2002:a9fe:a9fe::"}, nil
	}
	t.Cleanup(func() { defaultMCPDialLookupHost = origLookup })
	scannerless := newMetadataSafeDialContext(nil, func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("scannerless mixed metadata answer was dialed")
		return nil, nil
	})
	_, err := scannerless(context.Background(), "tcp", "metadata.vendor.example:80")
	assertMetadataDialBlock(t, err)
}

func TestMetadataSafeDialContext_AllowsNonMetadataTranslations(t *testing.T) {
	allowed := []string{
		"[64:ff9b::808:808]:443",
		"[64:ff9b::a00:1]:443",
		"[64:ff9b::a9fe:101]:443",
		"[64:ff9b:1::808:808]:443",
		"[64:ff9b:1:abcd:0:5431:808:808]:443",
		"[64:ff9b:1::a9fe:a9fe]:443",
	}
	for _, tc := range []struct {
		name    string
		disable bool
	}{
		{name: "ssrf disabled", disable: true},
		{name: "ssrf configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Defaults()
			if tc.disable {
				cfg.Internal = nil
			}
			sc := scanner.MustNew(cfg)
			t.Cleanup(sc.Close)
			for _, addr := range allowed {
				var dialed string
				dial := newMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(_ context.Context, _ string, got string) (net.Conn, error) {
					dialed = got
					client, server := net.Pipe()
					_ = server.Close()
					return client, nil
				})
				conn, err := dial(context.Background(), "tcp", addr)
				if err != nil {
					t.Fatalf("%s blocked: %v", addr, err)
				}
				_ = conn.Close()
				if dialed != addr {
					t.Fatalf("dialed %q, want %q", dialed, addr)
				}
			}
		})
	}

	cfg := config.Defaults()
	cfg.Internal = nil
	cfg.DNS.HostOverrides = map[string][]string{
		"public.vendor.example":   {"64:ff9b::808:808"},
		"private.vendor.example":  {"64:ff9b::a00:1"},
		"localuse.vendor.example": {"64:ff9b:1::808:808", "8.8.8.8"},
	}
	sc := scanner.MustNew(cfg)
	t.Cleanup(sc.Close)
	for host, ips := range cfg.DNS.HostOverrides {
		var dialed []string
		dial := newMetadataSafeDialContext(func() *scanner.Scanner { return sc }, func(_ context.Context, _ string, addr string) (net.Conn, error) {
			dialed = append(dialed, addr)
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		})
		conn, err := dial(context.Background(), "tcp", net.JoinHostPort(host, "443"))
		if err != nil {
			t.Fatalf("%s blocked: %v", host, err)
		}
		_ = conn.Close()
		want := net.JoinHostPort(net.ParseIP(ips[0]).String(), "443")
		if len(dialed) != 1 || dialed[0] != want {
			t.Fatalf("%s dialed %v, want [%s]", host, dialed, want)
		}
	}
}

func assertMetadataDialBlock(t *testing.T, err error) {
	t.Helper()
	var block *MetadataDialBlockError
	if !errors.As(err, &block) {
		t.Fatalf("dial error = %v, want MetadataDialBlockError", err)
	}
	if !strings.Contains(block.Error(), "ssrf_metadata") {
		t.Fatalf("dial error = %v, want ssrf_metadata classification", err)
	}
}
