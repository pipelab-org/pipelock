// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonnumber"
)

// JoinResponseCardViews joins already type-preserving card views at explicit
// string boundaries. Raw strings must escape the boundary marker namespace
// before entering this helper. Separators inside each view remain untouched.
func JoinResponseCardViews(parts ...string) string {
	return strings.Join(parts, jsonnumber.StringBoundary)
}
