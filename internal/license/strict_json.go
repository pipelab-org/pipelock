// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package license

import (
	"encoding/json"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// decodeLicenseJSON preserves forward-compatible unknown fields while rejecting
// duplicate members and noncanonical typed field names before decoding.
func decodeLicenseJSON(data []byte, out any) error {
	if err := jsonscan.RejectNonCanonicalFields(data, out); err != nil {
		return err
	}
	return json.Unmarshal(data, out)
}
