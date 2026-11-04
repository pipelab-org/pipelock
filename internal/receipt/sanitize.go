// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"net/url"
	"strings"
	"unicode"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// redactedTarget replaces content that cannot safely be retained in signed
// evidence. It differs from the recorder's post-sign "[REDACTED]" tombstone:
// this marker is signed normally and the receipt still verifies.
const redactedTarget = "[redacted-target]"

// dlpClean reports whether text is free of DLP matches. It wraps the same
// redaction function the recorder uses so the emitter's pre-sign sanitization
// is guaranteed consistent with the recorder's post-sign scan.
type dlpClean func(string) bool

// sanitizeTarget reduces URL targets to scheme and authority before signing,
// using the audit-log destination policy. Userinfo, path, query and fragment
// are dropped even when DLP does not recognize their content or is disabled.
// CONNECT authorities and opaque MCP tool names keep their existing spelling.
// A non-nil clean predicate additionally redacts unsafe retained content.
func sanitizeTarget(target string, clean dlpClean) string {
	// These exact producer constants are protocol identifiers, not URLs
	// supplied by a request. Their spelling is part of lifecycle verification.
	switch target {
	case sessionOpenTarget, sessionHeartbeatTarget, sessionCloseTarget:
		return target
	}
	switch {
	case mcpServerTarget(target):
		// Producer-synthesized, operator-named identifier; see mcpServerTarget.
	case strings.Contains(target, "://") || strings.HasPrefix(target, "//"):
		target = destination.RedactURLTarget(target)
	}
	if target == "" || clean == nil {
		return target
	}
	return cleanOrRedacted(target, clean)
}

// sanitizeSignedTarget is sanitizeTarget for values that enter a signed
// receipt. A signed target must never keep request content, so it also reduces
// URL syntax that is not an absolute URL: an origin-form request target (RFC
// 9112 section 3.2.1; inbound server-side request URLs such as "/path?query"
// carry no scheme or host), any value holding the query or fragment delimiter
// (RFC 3986 sections 3.4 and 3.5), and a scheme followed directly by an
// absolute path (see schemePathAbsolute). These have no destination, so they
// reduce to the redaction marker. Bare CONNECT authorities and opaque tool
// names hold none of these and keep their spelling.
//
// sanitizeTarget alone serves diagnostic output that reads unsigned logs, where
// relative targets keep their non-secret context.
func sanitizeSignedTarget(target string, clean dlpClean) string {
	if !mcpServerTarget(target) && !strings.Contains(target, "://") &&
		(strings.HasPrefix(target, "/") || strings.ContainsAny(target, "?#") || schemePathAbsolute(target)) {
		target = destination.RedactURLTarget(target)
	}
	return sanitizeTarget(target, clean)
}

// schemePathAbsolute reports a scheme followed directly by an absolute path
// with no "//" authority, such as "https:/opaque-segment" (RFC 3986 section 3,
// the path-absolute form of hier-part). url.URL.String produces this spelling
// for a URL with a scheme and path but no host. Bare CONNECT authorities
// ("host:443") and colon-bearing tool names ("server:tool") parse with an
// opaque part instead, so they keep their spelling.
func schemePathAbsolute(target string) bool {
	u, err := url.Parse(target)
	return err == nil && u.Scheme != "" && u.Opaque == "" && u.Host == "" && strings.HasPrefix(u.Path, "/")
}

// mcpServerTarget reports whether target is one of the two MCP producer
// targets built from an operator-chosen server name: "mcp://<server>/response"
// (internal/mcp/opts.go) and "mcp://<server>/tools/list"
// (internal/mcp/proxy.go). validateMCPServerName permits any non-space name
// without slashes, so the name is an identifier, not a DNS host, and the DNS
// authority check would collapse names such as "my_server" to the marker. The
// name must be free of URL delimiters, userinfo marker and whitespace so a
// request-supplied URL cannot ride this exemption.
func mcpServerTarget(target string) bool {
	rest, ok := strings.CutPrefix(target, "mcp://")
	if !ok {
		return false
	}
	name, ok := strings.CutSuffix(rest, "/response")
	if !ok {
		name, ok = strings.CutSuffix(rest, "/tools/list")
	}
	if !ok || name == "" || strings.ContainsAny(name, "/?#@\\") {
		return false
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// cleanOrRedacted returns s unchanged when DLP-clean, else the coarse marker.
func cleanOrRedacted(s string, clean dlpClean) string {
	if clean(s) {
		return s
	}
	return redactedTarget
}

// SanitizeTarget exposes the v1 emitter's pre-sign target sanitization to the
// v2 proxy_decision emitter (internal/contract/proxydecision). The v2 receipt
// stamps the same secret-bearing target field into a SIGNED payload, so it MUST
// apply byte-identical sanitization (#676) rather than duplicate this
// security-critical logic. A nil clean predicate disables DLP scanning of the
// retained destination; URL content segments are still dropped.
func SanitizeTarget(target string, clean func(string) bool) string {
	if clean == nil {
		return sanitizeTarget(target, nil)
	}
	return sanitizeTarget(target, dlpClean(clean))
}

// CleanOrRedacted exposes the v1 emitter's pre-sign field sanitization for
// non-URL secret-bearing fields (e.g. a scanner pattern/rule label that may
// echo matched bytes). Same rationale as SanitizeTarget: the v2 emitter signs
// these fields, so it reuses this function instead of duplicating it.
func CleanOrRedacted(s string, clean func(string) bool) string {
	if clean == nil {
		return s
	}
	return cleanOrRedacted(s, dlpClean(clean))
}

// SanitizeSignedTarget is SanitizeTarget for a value that will be signed into
// a receipt: it additionally reduces origin-form and query-bearing values (see
// sanitizeSignedTarget). The v2 proxy_decision emitter calls it so both
// receipt formats share one signed-target policy.
func SanitizeSignedTarget(target string, clean func(string) bool) string {
	if clean == nil {
		return sanitizeSignedTarget(target, nil)
	}
	return sanitizeSignedTarget(target, dlpClean(clean))
}
