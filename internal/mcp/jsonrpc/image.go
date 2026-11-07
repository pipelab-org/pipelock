// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/media"
)

// ExtractDLPStringsFromJSONResult preserves image declarations for scan views
// while the generic extractor continues returning the original scalar values.
func ExtractDLPStringsFromJSONResult(raw json.RawMessage) ExtractStringsResult {
	return ExtractStringsFromJSONResult(media.ImageDataURLView(raw))
}
