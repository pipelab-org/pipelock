// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"regexp"
	"strings"
	"sync"
)

// Different decoder branches can emit identical guarded windows at different
// positions. Only cache empty raw regexp results for exactly matching bytes.
// The cache belongs to one decode walk and never shares verdicts or spans.
type responseChainWindowMemo struct {
	mu       sync.Mutex
	negative map[responseChainWindowKey]struct{}
	bytes    int
}

type responseChainWindowKey struct {
	re   *regexp.Regexp
	text string
}

const (
	responseChainWindowMemoMaxWindow  = 16 << 10
	responseChainWindowMemoMaxBytes   = 2 << 20
	responseChainWindowMemoMaxEntries = 4096
)

func (m *responseChainWindowMemo) contains(re *regexp.Regexp, text string) bool {
	if m == nil || len(text) > responseChainWindowMemoMaxWindow {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.negative[responseChainWindowKey{re, text}]
	return ok
}

func (m *responseChainWindowMemo) add(re *regexp.Regexp, text string) {
	if m == nil || len(text) > responseChainWindowMemoMaxWindow {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.negative) >= responseChainWindowMemoMaxEntries || m.bytes+len(text) > responseChainWindowMemoMaxBytes {
		return
	}
	key := responseChainWindowKey{re, text}
	if _, ok := m.negative[key]; ok {
		return
	}
	key.text = strings.Clone(text)
	if m.negative == nil {
		m.negative = make(map[responseChainWindowKey]struct{})
	}
	m.negative[key] = struct{}{}
	m.bytes += len(text)
}
