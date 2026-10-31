// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

// DecodedTextDLPViews exposes only candidates already admitted by the text-DLP
// fixpoint decoder. Upload inspection uses these for existing JSON string
// carriers; it doesn't introduce attachment-field names or another decoder.
func DecodedTextDLPViews(text string) []string {
	decoded := decodeEncodingsFixpoint(text, true)
	views := make([]string, 0, len(decoded))
	for _, d := range decoded {
		views = append(views, d.text)
	}
	return views
}
