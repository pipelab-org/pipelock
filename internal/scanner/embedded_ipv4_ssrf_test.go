// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"context"
	"net"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestSSRFChecksEmbeddedIPv4(t *testing.T) {
	cfg := config.Defaults()
	s := MustNew(cfg)
	defer s.Close()
	internal := []string{
		"64:ff9b::7f00:1", "64:ff9b::a00:1", "2002:7f00:1::", "2002:a00:1::1",
		"::127.0.0.1", "::10.0.0.1", "2001:0:a00:1::f5ff:fffe",
		"2001:0:a00:1::f7f7:f7f7", "2001:0:808:808::f5ff:fffe", // server only, client only
	}
	for _, ip := range internal {
		if !s.IsInternalIP(net.ParseIP(ip)) {
			t.Errorf("IsInternalIP(%s) = false; embedded IPv4 is internal", ip)
		}
		if r := s.Scan(context.Background(), "http://["+ip+"]/"); r.Allowed {
			t.Errorf("literal [%s] allowed", ip)
		}
		rs, err := NewWithOptions(cfg, Options{UpstreamResolver: &fakeResolver{hosts: map[string][]string{"public.example.com": {ip}}}})
		if err != nil {
			t.Fatal(err)
		}
		if r := rs.Scan(context.Background(), "https://public.example.com/"); r.Allowed {
			t.Errorf("resolved answer %s allowed", ip)
		}
		rs.Close()
	}
	for _, ip := range []string{
		"64:ff9b::808:808", "2002:808:808::1", "2001:0:808:808::f7f7:f7f7",
	} {
		if s.IsInternalIP(net.ParseIP(ip)) {
			t.Errorf("IsInternalIP(%s) = true; embedded IPv4 is public", ip)
		}
	}
}

// Allowlisting the outer translated address does not exempt an internal
// IPv4 host behind it; allowlisting the IPv4 host does.
func TestIPAllowlistWithEmbeddedIPv4(t *testing.T) {
	cfg := config.Defaults()
	cfg.SSRF.IPAllowlist = []string{"64:ff9b::/96"}
	s := MustNew(cfg)
	if s.IsIPAllowlisted(nil) {
		t.Error("nil address must not be allowlisted")
	}
	if s.IsIPAllowlisted(net.ParseIP("64:ff9b::a00:1")) {
		t.Error("outer allowlist must not exempt embedded 10.0.0.1")
	}
	s.Close()

	cfg = config.Defaults()
	cfg.SSRF.IPAllowlist = []string{"10.0.0.0/8"}
	s = MustNew(cfg)
	defer s.Close()
	if !s.IsIPAllowlisted(net.ParseIP("64:ff9b::a00:1")) {
		t.Error("allowlisted embedded 10.0.0.1 should be exempt")
	}
}

// A local-use NAT64 address has no fixed embedding. Without a configured
// translator prefix it is ordinary IPv6 on both the literal path and the
// resolved path, including when configured SSRF is off.
func TestLocalUseNAT64WithoutPrefixIsOrdinaryIPv6(t *testing.T) {
	addresses := []string{
		"64:ff9b:1::808:808",
		"64:ff9b:1:abcd:0:5431:808:808",
		"64:ff9b:1::a9fe:a9fe",
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
			s := MustNew(cfg)
			t.Cleanup(func() { s.Close() })
			for _, ip := range addresses {
				if s.IsInternalIP(net.ParseIP(ip)) {
					t.Errorf("IsInternalIP(%s) = true; local-use address decoded without a prefix", ip)
				}
				if r := s.Scan(context.Background(), "http://["+ip+"]/"); !r.Allowed {
					t.Errorf("literal [%s] blocked: %s (%s)", ip, r.Reason, r.Scanner)
				}
				rs, err := NewWithOptions(cfg, Options{UpstreamResolver: &fakeResolver{hosts: map[string][]string{
					"public.example.com": {ip},
				}}})
				if err != nil {
					t.Fatal(err)
				}
				if r := rs.Scan(context.Background(), "https://public.example.com/"); !r.Allowed {
					t.Errorf("resolved %s blocked: %s (%s)", ip, r.Reason, r.Scanner)
				}
				rs.Close()
			}
		})
	}
}

// Fixed-layout metadata must use the metadata classification, not only the
// generic internal-address block. The disabled-SSRF literal floor still denies.
func TestEmbeddedMetadataUsesMetadataClassification(t *testing.T) {
	addresses := []string{
		"64:ff9b::a9fe:a9fe",
		"64:ff9b::a83f:8110",
		"64:ff9b::6464:64c8",
		"2002:a9fe:a9fe::",
		"::169.254.169.254",
		"2001:0:a9fe:a9fe::",
		"2001::5601:5601",
	}
	cfg := config.Defaults()
	s := MustNew(cfg)
	t.Cleanup(func() { s.Close() })
	for _, ip := range addresses {
		r := s.Scan(context.Background(), "http://["+ip+"]/")
		if r.Allowed || r.Scanner != ScannerSSRFMetadata {
			t.Errorf("literal [%s] allowed=%v scanner=%s reason=%s", ip, r.Allowed, r.Scanner, r.Reason)
		}
		rs, err := NewWithOptions(cfg, Options{UpstreamResolver: &fakeResolver{hosts: map[string][]string{
			"metadata.vendor.example": {ip},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		r = rs.Scan(context.Background(), "https://metadata.vendor.example/")
		if r.Allowed || r.Scanner != ScannerSSRFMetadata {
			t.Errorf("resolved %s allowed=%v scanner=%s reason=%s", ip, r.Allowed, r.Scanner, r.Reason)
		}
		rs.Close()
	}

	disabled := config.Defaults()
	disabled.Internal = nil
	floor := MustNew(disabled)
	t.Cleanup(func() { floor.Close() })
	if r := floor.Scan(context.Background(), "http://[64:ff9b::a9fe:a9fe]/"); r.Allowed {
		t.Fatal("core floor allowed a well-known-prefix metadata literal with SSRF disabled")
	}
}
