// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package destination

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// RedactURLContent removes the query and fragment from raw, and removes
// the path as well unless keepPath is set. A value that does not parse as an
// absolute URL is parsed as a schemeless authority, so CONNECT destinations
// survive while opaque payloads and malformed destinations are redacted.
// Ambiguous single-label host:port text is redacted except for localhost;
// callers can use an explicit URL or //authority for other single-label hosts.
func RedactURLContent(raw string, keepPath bool) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		u, err = url.Parse("//" + raw)
		if err == nil && u.Port() != "" && !strings.Contains(u.Hostname(), ".") &&
			!strings.Contains(u.Hostname(), ":") && !strings.EqualFold(u.Hostname(), "localhost") {
			return "[redacted-url]"
		}
	}
	if err != nil {
		return "[redacted-url]"
	}
	switch strings.ToLower(u.Scheme) {
	case "", "http", "https", "ws", "wss":
	default:
		return "[redacted-url]"
	}
	return redactURLDestination(u, keepPath)
}

// RedactURLTarget reduces a URL-shaped receipt target to its destination.
// Receipt transports also use protocol identifiers such as mcp://, so their
// schemes are retained. Audit callers keep their narrower scheme policy.
func RedactURLTarget(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "[redacted-url]"
	}
	return redactURLDestination(u, false)
}

func redactURLDestination(u *url.URL, keepPath bool) string {
	if !validRedactionAuthority(u) {
		return "[redacted-url]"
	}
	out := u.Host
	if u.Scheme != "" {
		out = u.Scheme + "://" + u.Host
	}
	if keepPath {
		out += u.EscapedPath()
	}
	return out
}

// validRedactionAuthority accepts DNS names and IP literals with an optional
// numeric port. URL parsing alone also accepts opaque scheme-shaped inputs
// and malformed DNS labels, which must not become destination diagnostics.
func validRedactionAuthority(u *url.URL) bool {
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if port := u.Port(); port != "" {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 {
			return false
		}
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Zone() == ""
	}
	if strings.ContainsAny(host, "[]:") || strings.HasPrefix(u.Host, "[") {
		return false
	}
	ascii, err := LookupASCII(host)
	if err != nil {
		return false
	}
	ascii = strings.TrimSuffix(ascii, ".")
	if ascii == "" || len(ascii) > 253 {
		return false
	}
	for label := range strings.SplitSeq(ascii, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' {
				continue
			}
			return false
		}
	}
	return true
}
