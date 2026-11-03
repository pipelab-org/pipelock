// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"strings"

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
	if strings.Contains(target, "://") || strings.HasPrefix(target, "//") {
		target = destination.RedactURLTarget(target)
	}
	if target == "" || clean == nil {
		return target
	}
	return cleanOrRedacted(target, clean)
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
