// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/json"
	"regexp"
	"slices"
	"testing"
)

func TestExtractorsKeepOutOfRangeNumberDocuments(t *testing.T) {
	raw := json.RawMessage(`{"n":1e400,"text":"value"}`)
	if got := ExtractStringsFromJSONResult(raw).Strings; !slices.Equal(got, []string{"value"}) {
		t.Fatalf("ExtractStringsFromJSONResult = %q", got)
	}
	if got := ExtractStringsForKeysResult(raw, regexp.MustCompile(`^text$`)).Strings; !slices.Equal(got, []string{"value"}) {
		t.Fatalf("ExtractStringsForKeysResult = %q", got)
	}
	if got := ExtractKeysFromJSONResult(raw).Keys; !slices.Contains(got, "text") {
		t.Fatalf("ExtractKeysFromJSONResult = %q", got)
	}
}
