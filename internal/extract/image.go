// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/media"
)

// AllDLPStringsFromJSONResult preserves declared image carriers in a scan-only
// view. The generic extractor retains its exact-value contract for consumers
// such as tool policy and replay. Numbers, keys and depth checks are unchanged.
func AllDLPStringsFromJSONResult(raw json.RawMessage) JSONStringsResult {
	return AllStringsFromJSONResult(media.ImageDataURLView(raw))
}
