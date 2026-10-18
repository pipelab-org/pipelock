// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import "net"

// EmbeddedIPv4 returns the IPv4 addresses carried inside an IPv6 address by
// the standard translation and tunnelling formats, so SSRF checks can judge
// the IPv4 host a gateway would actually reach:
//
//   - NAT64 well-known prefix 64:ff9b::/96 (RFC 6052)
//   - NAT64 local-use prefix 64:ff9b:1::/48 (RFC 8215). RFC 6052 section 2.2
//     allows prefix lengths 48, 56, 64, and 96 inside that reservation, and
//     this process has no configured length, so every length that keeps the
//     required zero octet is returned. RFC 8215 section 5 forbids assuming
//     one embedded-IPv4 position.
//   - 6to4 2002::/16 (RFC 3056)
//   - Teredo 2001::/32 (RFC 4380), both server and client addresses
//   - IPv4-compatible ::a.b.c.d (RFC 4291, deprecated), except :: and ::1
//
// IPv4-mapped ::ffff:a.b.c.d is not listed: net.IP.To4 already unwraps it.
// It returns nil for any other address.
func EmbeddedIPv4(ip net.IP) []net.IP {
	if ip == nil || ip.To4() != nil {
		return nil
	}
	b := ip.To16()
	if b == nil {
		return nil
	}
	v4 := func(a, b2, c, d byte) net.IP { return net.IPv4(a, b2, c, d).To4() }
	zero := func(from, to int) bool {
		for i := from; i < to; i++ {
			if b[i] != 0 {
				return false
			}
		}
		return true
	}
	switch {
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && zero(4, 12):
		return []net.IP{v4(b[12], b[13], b[14], b[15])}
	case b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0x00 && b[5] == 0x01 && b[8] == 0x00:
		// Bits 64-71 are the RFC 6052 "u" octet and MUST be zero at every
		// allowed length, including /96. A nonzero suffix is still decoded:
		// a receiver SHOULD ignore those bits and continue. Lengths shorter
		// than /48 would treat the reserved prefix itself as IPv4, so they
		// are not readings of this prefix.
		var found []net.IP
		found = appendUniqueIPv4(found, v4(b[12], b[13], b[14], b[15])) // /96
		found = appendUniqueIPv4(found, v4(b[9], b[10], b[11], b[12]))  // /64
		found = appendUniqueIPv4(found, v4(b[7], b[9], b[10], b[11]))   // /56
		found = appendUniqueIPv4(found, v4(b[6], b[7], b[9], b[10]))    // /48
		return found
	case b[0] == 0x20 && b[1] == 0x02:
		return []net.IP{v4(b[2], b[3], b[4], b[5])}
	case b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00:
		return []net.IP{
			v4(b[4], b[5], b[6], b[7]),
			v4(b[12]^0xff, b[13]^0xff, b[14]^0xff, b[15]^0xff),
		}
	case zero(0, 12) && !zero(12, 15):
		return []net.IP{v4(b[12], b[13], b[14], b[15])}
	case zero(0, 12) && b[15] > 1:
		return []net.IP{v4(b[12], b[13], b[14], b[15])}
	}
	return nil
}

func appendUniqueIPv4(dst []net.IP, ip net.IP) []net.IP {
	for _, have := range dst {
		if have.Equal(ip) {
			return dst
		}
	}
	return append(dst, ip)
}

// SSRFForms returns the normalized address followed by any IPv4 addresses
// embedded in it. An SSRF check must hold for every form.
func SSRFForms(ip net.IP) []net.IP {
	if ip == nil {
		return nil
	}
	return append([]net.IP{NormalizeIP(ip)}, EmbeddedIPv4(ip)...)
}

// ContainsAnySSRFForm reports whether cidr contains ip or an IPv4 address
// embedded in it.
func ContainsAnySSRFForm(cidr *net.IPNet, ip net.IP) bool {
	for _, form := range SSRFForms(ip) {
		if cidr.Contains(form) {
			return true
		}
	}
	return false
}
