// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"context"
	"net"
	"net/url"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

// shellReplacesConfiguredSSRF reports whether a URL refusal is the configured
// private-address SSRF stage, or a hostname that the same stage classified as
// cloud metadata. Literal metadata addresses stay on the scan result.
func shellReplacesConfiguredSSRF(floorURL string, result scanner.Result) bool {
	if result.Scanner == scanner.ScannerSSRF {
		return true
	}
	if result.Scanner != scanner.ScannerSSRFMetadata {
		return false
	}
	host := shellDestinationHost(floorURL)
	return host != "" && scanner.ParseIPLiteral(host) == nil
}

// shellConfiguredSSRFEvidence replaces a configured private-address refusal.
// Loopback, RFC 1918, CGNAT, ULA, and the unspecified address are the
// developer's own services. A cloud-metadata address or a link-local address
// is still a refusal, and a lookup that does not answer is a warning.
func shellConfiguredSSRFEvidence(ctx context.Context, sc *scanner.Scanner, floorURL string, result scanner.Result) []Evidence {
	host := shellDestinationHost(floorURL)
	if host == "" {
		return markShellMetadataFloor(scanDestinationEvidence(result, sc, floorURL))
	}
	if ip := scanner.ParseIPLiteral(host); ip != nil {
		if shellHookMetadataOrLinkLocal(ip) {
			return shellHookFloorEvidence(host, ip)
		}
		return nil
	}
	looked := shellMetadataLookup(ctx, sc, host)
	// The scan already classified this name as metadata. A later lookup that
	// misses that address must not release it.
	if result.Scanner == scanner.ScannerSSRFMetadata && !shellEvidenceRefuses(looked) {
		return markShellMetadataFloor(scanDestinationEvidence(result, sc, floorURL))
	}
	return looked
}

// shellMetadataLookup resolves host and applies the hook metadata floor.
// A cancelled context refuses. A lookup that does not answer warns.
func shellMetadataLookup(ctx context.Context, sc *scanner.Scanner, host string) []Evidence {
	if ctx != nil && ctx.Err() != nil {
		return shellContextEvidence()
	}
	ips, err := sc.LookupDialHost(ctx, host)
	if err != nil {
		if ctx != nil && ctx.Err() != nil {
			return shellContextEvidence()
		}
		return shellUnresolvedEvidence(host)
	}
	parsed := destination.ParseResolved(ips)
	if len(parsed) == 0 {
		return shellUnresolvedEvidence(host)
	}
	for _, addr := range parsed {
		if shellHookMetadataOrLinkLocal(addr.IP) {
			return shellHookFloorEvidence(host, addr.IP)
		}
	}
	return nil
}

func shellEvidenceRefuses(ev []Evidence) bool {
	for _, e := range ev {
		if e.Action == config.ActionBlock || e.core || e.inspectionIncomplete {
			return true
		}
	}
	return false
}

func shellDestinationHost(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// shellHookMetadataOrLinkLocal is the hook destination floor. Metadata matches
// the MCP dialer (scanner.IsCloudMetadataIP, including embedded forms).
// Link-local unicast is the rest of 169.254.0.0/16 and fe80::/10, which that
// dialer does not treat as metadata. Multicast stays refused too: it is not
// one of the private ranges a hook may reach, and dropping the scan's
// refusal would weaken that floor. The unspecified address is the exception
// the hook allows.
func shellHookMetadataOrLinkLocal(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if scanner.IsCloudMetadataIP(ip) {
		return true
	}
	for _, form := range destination.SSRFForms(ip) {
		if form == nil || form.IsUnspecified() {
			continue
		}
		if form.IsLinkLocalUnicast() || form.IsLinkLocalMulticast() ||
			form.IsInterfaceLocalMulticast() || form.IsMulticast() {
			return true
		}
	}
	return false
}

func shellHookFloorEvidence(host string, ip net.IP) []Evidence {
	label := scanner.ScannerSSRF
	pattern := "SSRF blocked: " + host + " resolves to link-local address " + ip.String()
	if scanner.IsCloudMetadataIP(ip) {
		label = scanner.ScannerSSRFMetadata
		pattern = "SSRF blocked: " + host + " resolves to cloud metadata endpoint " + ip.String()
	}
	return []Evidence{{
		Scanner:  label,
		Pattern:  pattern,
		Severity: config.SeverityCritical,
		Action:   config.ActionBlock,
		core:     true,
	}}
}

func shellUnresolvedEvidence(host string) []Evidence {
	return []Evidence{{
		Scanner:  scanner.ScannerSSRF,
		Pattern:  "unresolved shell destination host " + host,
		Severity: config.SeverityWarn,
		Detail:   "DNS lookup failed; literal metadata addresses stay blocked",
		Action:   config.ActionWarn,
	}}
}

func shellContextEvidence() []Evidence {
	return []Evidence{{
		Scanner:              scanner.ScannerContext,
		Pattern:              "request context cancelled",
		Severity:             config.SeverityHigh,
		Action:               config.ActionBlock,
		inspectionIncomplete: true,
	}}
}

// markShellMetadataFloor makes a metadata refusal from the URL scan core-style
// so audit mode still denies it. The metadata floor's severity is critical.
func markShellMetadataFloor(ev []Evidence) []Evidence {
	for i := range ev {
		if ev[i].Scanner == scanner.ScannerSSRFMetadata {
			ev[i].core = true
			ev[i].Severity = config.SeverityCritical
		}
	}
	return ev
}
