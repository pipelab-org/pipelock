// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net"
	"slices"
	"testing"
)

func TestEmbeddedIPv4(t *testing.T) {
	for in, want := range map[string][]string{
		"64:ff9b::7f00:1":   {"127.0.0.1"},
		"64:ff9b::10.0.0.1": {"10.0.0.1"},
		// RFC 8215 local prefix, every RFC 6052 length with a zero u octet.
		// Order is /96, /64, /56, /48, with duplicates removed.
		"64:ff9b:1::a9fe:a9fe":      {"169.254.169.254", "0.0.0.169", "0.0.0.0"},
		"64:ff9b:1:a00:1:100::":     {"0.0.0.0", "1.1.0.0", "0.1.1.0", "10.0.1.1"},
		"64:ff9b:1:abcd::a00:1":     {"10.0.0.1", "0.0.0.10", "205.0.0.0", "171.205.0.0"},
		"64:ff9b:1:fffd:1::808:808": {"8.8.8.8", "1.0.0.8", "253.1.0.0", "255.253.1.0"},
		// Nonzero u octet: not an RFC 6052 embedding.
		"64:ff9b:1:a00:100:1::":     nil,
		"2002:7f00:1::":             {"127.0.0.1"},
		"2002:a9fe:a9fe::1":         {"169.254.169.254"},
		"2001:0:a00:1::f5ff:fffe":   {"10.0.0.1", "10.0.0.1"},
		"2001:0:a00:1::f7f7:f7f7":   {"10.0.0.1", "8.8.8.8"},
		"2001:0:808:808::f5ff:fffe": {"8.8.8.8", "10.0.0.1"},
		"::127.0.0.1":               {"127.0.0.1"},
		"::10.1.2.3":                {"10.1.2.3"},
		"::2":                       {"0.0.0.2"},
		"::":                        nil,
		"::1":                       nil,
		"::ffff:127.0.0.1":          nil,
		"2606:4700::1111":           nil,
		"10.0.0.1":                  nil,
	} {
		var got []string
		for _, ip := range EmbeddedIPv4(net.ParseIP(in)) {
			got = append(got, ip.String())
		}
		if !slices.Equal(got, want) {
			t.Errorf("EmbeddedIPv4(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestNonOverridableFloorChecksEmbeddedIPv4(t *testing.T) {
	for _, s := range []string{"64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::", "::169.254.169.254", "64:ff9b::e000:1"} {
		if !IsNonOverridableSSRFTarget(net.ParseIP(s)) {
			t.Errorf("%s embeds a non-overridable IPv4 target", s)
		}
	}
	if IsNonOverridableSSRFTarget(net.ParseIP("64:ff9b::808:808")) {
		t.Error("64:ff9b::808:808 embeds a public address")
	}
}
