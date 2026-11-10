// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net"
	"net/url"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/destination"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

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
