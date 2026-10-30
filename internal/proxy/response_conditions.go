// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/blockreason"
)

// applyFullResponsePolicy prepares an outbound request when headers are supplied,
// and checks an origin response when resp is supplied. Client cache validators
// do not prove approval of a complete representation. Remove Range with If-Range
// so dropping a stale validator cannot turn a full response into a slice.
// Neither a bodyless 304 nor a partial 206 establishes approval of the full
// representation. Refuse both before relaying any origin headers or status.
// This does not alter WebSocket upgrade headers.
func applyFullResponsePolicy(headers http.Header, resp *http.Response) bool {
	for _, name := range []string{"If-None-Match", "If-Modified-Since", "If-Range", "Range"} {
		headers.Del(name)
	}
	return resp == nil || (resp.StatusCode != http.StatusNotModified && resp.StatusCode != http.StatusPartialContent)
}

// fullResponseRefusal identifies the incomplete representation without treating
// the refusal as an upstream outage or an injection finding.
func fullResponseRefusal(resp *http.Response) string {
	if resp.StatusCode == http.StatusPartialContent {
		return "unbound partial response; request the complete resource"
	}
	return "unbound not-modified response; request the complete resource"
}

// writeFullResponseBlock uses the same synthetic response as the reverse path,
// including its block metadata, without copying any origin headers.
func writeFullResponseBlock(w http.ResponseWriter, requestID string) {
	resp := &http.Response{Header: make(http.Header)}
	replaceWithBlockReason(resp, string(blockreason.ResponseIncomplete), blockInfoFor(blockreason.ResponseIncomplete, "browser_cache").WithRequestID(requestID))
	for name, values := range resp.Header {
		w.Header()[name] = values
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = resp.Body.Close()
}

const unsupportedRangeMessage = "Finite, suffix and multiple Range requests are not supported through inspection; request the complete resource without Range"

// unsupportedInspectionRange refuses partial-representation intent before any
// origin transfer. Range is removed before forwarding, so a permitted request
// receives the complete representation as a 200, which RFC 9110 section 15.3.1
// defines as the full representation rather than a slice. RFC 9110 section 14.2
// requires Range to be ignored on non-GET methods.
//
// A single open-ended byte range (bytes=N-) stays permitted: resuming clients
// that check for 206 restart on a 200 instead of failing. Finite, suffix and
// multiple ranges are refused, because a part downloader that writes the
// response at the requested offset would assemble a full replacement at the
// wrong position. If-Range cannot authorize a slice without an approved
// complete representation.
func unsupportedInspectionRange(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	values := r.Header.Values("Range")
	if len(values) == 1 && openEndedByteRange(values[0]) {
		return false
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// openEndedByteRange reports whether value is exactly one first-pos range in
// the bytes unit (RFC 9110 section 14.1.2 int-range with no last-pos). The
// range unit is case-insensitive (section 14.1).
func openEndedByteRange(value string) bool {
	unit, spec, ok := strings.Cut(strings.TrimSpace(value), "=")
	if !ok || !strings.EqualFold(unit, "bytes") {
		return false
	}
	first, last, ok := strings.Cut(spec, "-")
	if !ok || last != "" || first == "" {
		return false
	}
	for _, c := range first {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func writeUnsupportedRange(w http.ResponseWriter, requestID string) {
	writeBlockedError(w, blockInfoFor(blockreason.ResponseIncomplete, "browser_cache").WithRequestID(requestID), unsupportedRangeMessage, http.StatusForbidden)
}
