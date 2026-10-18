// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestAllStringsFromJSONResultOutOfRangeNumber(t *testing.T) {
	got := AllStringsFromJSONResult(json.RawMessage(`{"a":1e400,"b":"value","c":2.5}`))
	want := []string{"a", "1e400", "b", "value", "c", "2.5"}
	if !slices.Equal(got.Strings, want) || got.Truncated {
		t.Fatalf("got %q truncated=%v, want %q", got.Strings, got.Truncated, want)
	}
}

func TestDecodeJSONOutOfRangeNumber(t *testing.T) {
	var parsed any
	if err := DecodeJSON([]byte(`{"a":1e400}`), &parsed); err != nil {
		t.Fatalf("out-of-range number must decode: %v", err)
	}
	for _, bad := range []string{``, `{"a":1} {}`, `{"a":`, `[1,]`} {
		if err := DecodeJSON([]byte(bad), &parsed); err == nil {
			t.Fatalf("%q must not decode", bad)
		}
	}
}
