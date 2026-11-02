// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "github.com/luckyPipewrench/pipelock/internal/normalize"

type decodingMemoKey struct {
	text       string
	includeURL bool
	minPrefix  int
}

// decodingMemo shares immutable decoded and normalized views within one scan. It never
// stores findings, policy decisions or state on the Scanner. Reaching either
// existing decoder work bound stops retention, not decoding or detection.
//
// incomplete records that some decode or HTML entity chain in this scan
// stopped at a depth bound with decodable work left. It is a property of the
// scan, not of one view, so it survives cache hits and unretained decodes.
type decodingMemo struct {
	views         map[decodingMemoKey]memoDecode
	normalized    map[string]string
	retainedBytes int
	incomplete    bool
}

type memoDecode struct {
	views    []decodedResult
	complete bool
}

// markIncomplete records a bound reached outside the fixpoint decoder. A nil
// memo has no scan to mark; callers that need the signal pass a memo.
func (m *decodingMemo) markIncomplete() {
	if m != nil {
		m.incomplete = true
	}
}

// inspectionIncomplete reports whether any bound in this scan returned a
// partial result.
func (m *decodingMemo) inspectionIncomplete() bool {
	return m != nil && m.incomplete
}

// decodeHTML is decodeHTMLEntities that records a chain left undecoded at the
// pass limit.
func (m *decodingMemo) decodeHTML(text string) string {
	decoded, converged := decodeHTMLEntitiesChecked(text)
	if !converged {
		m.markIncomplete()
	}
	return decoded
}

func (m *decodingMemo) decode(text string, includeURL bool) []decodedResult {
	return m.decodeMode(text, includeURL, 0)
}

func (m *decodingMemo) decodeKnownSecret(text string, minimum int) []decodedResult {
	return m.decodeMode(text, true, minimum)
}

func (m *decodingMemo) decodeMode(text string, includeURL bool, minPrefix int) []decodedResult {
	if m == nil {
		decoded, _ := decodeEncodingsFixpointMode(text, includeURL, minPrefix)
		return decoded
	}
	key := decodingMemoKey{text: text, includeURL: includeURL, minPrefix: minPrefix}
	if cached, ok := m.views[key]; ok {
		if !cached.complete {
			m.incomplete = true
		}
		return cached.views
	}
	decoded, complete := decodeEncodingsFixpointMode(text, includeURL, minPrefix)
	if !complete {
		m.incomplete = true
	}
	if text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return decoded
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	cost := len(text)
	if cost > remaining {
		return decoded
	}
	for _, view := range decoded {
		if len(view.text) > remaining-cost {
			return decoded
		}
		cost += len(view.text)
	}
	if m.views == nil {
		m.views = make(map[decodingMemoKey]memoDecode)
	}
	m.views[key] = memoDecode{views: decoded, complete: complete}
	m.retainedBytes += cost
	return decoded
}

// normalize preserves each call's exact input and normalization depth. A
// normalized output is not treated as already normalized on a later call.
func (m *decodingMemo) normalize(text string) string {
	if m == nil {
		return normalize.ForDLP(text)
	}
	if normalized, ok := m.normalized[text]; ok {
		return normalized
	}
	normalized := normalize.ForDLP(text)
	if text == "" || len(m.views)+len(m.normalized) >= maxDecodeCandidates {
		return normalized
	}
	remaining := maxDecodeTotalBytes - m.retainedBytes
	if len(text) > remaining || len(normalized) > remaining-len(text) {
		return normalized
	}
	if m.normalized == nil {
		m.normalized = make(map[string]string)
	}
	m.normalized[text] = normalized
	m.retainedBytes += len(text) + len(normalized)
	return normalized
}
