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
	for _, ip := range []string{"64:ff9b::808:808", "2002:808:808::1", "2001:0:808:808::f7f7:f7f7"} {
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
