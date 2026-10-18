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
		"64:ff9b::7f00:1":           {"127.0.0.1"},
		"64:ff9b::10.0.0.1":         {"10.0.0.1"},
		"64:ff9b:1::a9fe:a9fe":      {"169.254.169.254"},
		"64:ff9b:1:a00:1:100::":     {"10.0.1.1"},
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
