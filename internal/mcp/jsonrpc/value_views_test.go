// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonrpc

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/extract"
)

// A decoded tree and its JSON round trip must expose identical values, card
// barriers, key order and media budget use. This is the round trip the response
// remainder used before consuming the decoded tree directly.
func TestExtractValueViewsRoundTrip(t *testing.T) {
	for _, raw := range []string{
		`null`, `""`, `[]`, `{}`, `[null,true,false,"",-0,1e10000,123456789012345678901]`,
		`{"z":["last",{"b":null,"a":"first"}],"a":"<>&\u2028\u2029","\u0062":"escaped"}`,
		`{"data":{"note":"visible"},"blob":["plain text",{"data":"more text"}],"raw":null}`,
		`{"unicode":"\ud800 \udc00 \ud83d\ude00","nul":"a\u0000b"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			var value any
			if err := extract.DecodeJSON([]byte(raw), &value); err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			var directBudget, encodedBudget MediaTextBudget
			got := ExtractVisibleStringsFromValueResult(value, &directBudget)
			want := ExtractVisibleStringsFromJSONResultWithMediaBudget(encoded, &encodedBudget)
			if !reflect.DeepEqual(got, want) || directBudget != encodedBudget {
				t.Fatalf("value = %+v, budget = %+v; round trip = %+v, budget = %+v", got, directBudget, want, encodedBudget)
			}
			if got, want := ExtractKeysFromValueResult(value), ExtractKeysFromJSONResult(encoded); !reflect.DeepEqual(got, want) {
				t.Fatalf("keys = %+v, round trip = %+v", got, want)
			}
		})
	}
}

func TestExtractValueViewsScalars(t *testing.T) {
	var value any
	if err := extract.DecodeJSON([]byte(`{"z":"last","a":["",null,true,false,-0,1e10000,123456789012345678901]}`), &value); err != nil {
		t.Fatal(err)
	}
	got := ExtractVisibleStringsFromValueResult(value, nil)
	if !reflect.DeepEqual(got.Strings, []string{"", "last"}) || !reflect.DeepEqual(got.StringPositions, []int{0, 7}) {
		t.Fatalf("strings or positions changed: %+v", got)
	}
	wantText := []string{"", Null, "true", "false", "-0", "1e10000", "123456789012345678901", "last"}
	if len(got.CardAtoms) != len(wantText) {
		t.Fatalf("atoms = %+v", got.CardAtoms)
	}
	for i, atom := range got.CardAtoms {
		if atom.Text != wantText[i] || atom.Number != (i >= 4 && i <= 6) || atom.Key {
			t.Errorf("atom %d = %+v, want text %q", i, atom, wantText[i])
		}
	}
	if keys := ExtractKeysFromValueResult(value); keys.Truncated || !reflect.DeepEqual(keys.Keys, []string{"a", "z"}) {
		t.Fatalf("sorted keys = %+v", keys)
	}
	for _, raw := range []string{`[]`, `{}`} {
		if err := extract.DecodeJSON([]byte(raw), &value); err != nil {
			t.Fatal(err)
		}
		if got := ExtractVisibleStringsFromValueResult(value, nil); !reflect.DeepEqual(got, ExtractStringsResult{}) {
			t.Fatalf("empty value = %+v", got)
		}
		if got := ExtractKeysFromValueResult(value); !reflect.DeepEqual(got, ExtractKeysResult{}) {
			t.Fatalf("empty keys = %+v", got)
		}
	}
}

func TestExtractValueViewsBounds(t *testing.T) {
	for _, depth := range []int{maxExtractDepth, maxExtractDepth + 1} {
		var value any
		raw := strings.Repeat("[", depth) + `"leaf"` + strings.Repeat("]", depth)
		if err := extract.DecodeJSON([]byte(raw), &value); err != nil {
			t.Fatal(err)
		}
		stringsResult := ExtractVisibleStringsFromValueResult(value, nil)
		keys := ExtractKeysFromValueResult(value)
		wantTruncated := depth > maxExtractDepth
		if stringsResult.Truncated != wantTruncated || keys.Truncated != wantTruncated {
			t.Fatalf("depth %d: strings = %+v, keys = %+v", depth, stringsResult, keys)
		}
		if wantTruncated && len(stringsResult.Strings) != 0 {
			t.Fatal("depth-limited extraction exposed an uninspected leaf")
		}
		if !wantTruncated && !reflect.DeepEqual(stringsResult.Strings, []string{"leaf"}) {
			t.Fatalf("boundary leaf missing: %+v", stringsResult)
		}
	}
	for _, width := range []int{maxExtractKeys - 1, maxExtractKeys, maxExtractKeys + 1} {
		object := make(map[string]any, width)
		for i := range width {
			object[fmt.Sprintf("k%05d", i)] = nil
		}
		// Construct the same types as DecodeJSON without serializing a wide map.
		got := ExtractKeysFromValueResult(object)
		if got.Truncated != (width >= maxExtractKeys) {
			t.Fatalf("width %d: truncated = %v", width, got.Truncated)
		}
		wantLength := width
		if width > maxExtractKeys {
			wantLength = 0 // Refuse before allocating/sorting an oversized map.
		}
		if len(got.Keys) != wantLength {
			t.Fatalf("width %d: keys = %d, want %d", width, len(got.Keys), wantLength)
		}
	}
	// A nested object can use the remaining allowance before a parent visits
	// its next array element or object member. Both loops must stop there.
	nested := make(map[string]any, maxExtractKeys-1)
	for i := range maxExtractKeys - 1 {
		nested[fmt.Sprintf("k%05d", i)] = nil
	}
	for _, value := range []any{
		[]any{map[string]any{"a": nested}, "unvisited"},
		map[string]any{"a": nested, "z": "unvisited"},
	} {
		got := ExtractKeysFromValueResult(value)
		if !got.Truncated || len(got.Keys) != maxExtractKeys || got.Keys[len(got.Keys)-1] == "z" {
			t.Fatalf("nested object exceeded the shared key allowance: %+v", got)
		}
	}
}

func TestExtractValueViewsMedia(t *testing.T) {
	for name, payload := range map[string][]byte{
		"plain":    []byte(mediaTestPhrase),
		"utf16":    utf16Encode(mediaTestPhrase, binary.LittleEndian),
		"controls": interleaved("decoded "+mediaTestPhrase, 0),
	} {
		t.Run(name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(append([]byte("GIF89a"), payload...))
			var value any
			raw, err := json.Marshal(map[string]any{"data": []any{encoded}, "raw": map[string]any{"note": "visible"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := extract.DecodeJSON(raw, &value); err != nil {
				t.Fatal(err)
			}
			var directBudget, encodedBudget MediaTextBudget
			got := ExtractVisibleStringsFromValueResult(value, &directBudget)
			want := ExtractVisibleStringsFromJSONResultWithMediaBudget(raw, &encodedBudget)
			if !reflect.DeepEqual(got, want) || directBudget != encodedBudget || directBudget.used == 0 {
				t.Fatalf("media parity: got %+v/%+v, want %+v/%+v", got, directBudget, want, encodedBudget)
			}
			if !strings.Contains(strings.Join(got.Strings, " "), mediaTestPhrase) || got.IncompleteReason != "" {
				t.Fatalf("decoded text missing: %+v", got)
			}
			if !strings.Contains(strings.Join(got.Strings, " "), "visible") {
				t.Fatal("a media key hid a nested object")
			}
			budget := MediaTextBudget{used: MaxMediaTextBytes - 1}
			if got := ExtractVisibleStringsFromValueResult(value, &budget); got.IncompleteReason != mediaTextBudgetExceeded || got.Strings != nil || got.CardAtoms != nil || got.StringPositions != nil {
				t.Fatalf("budget exhaustion returned partial output: %+v", got)
			}
		})
	}
	encoded := base64.StdEncoding.EncodeToString(append([]byte("GIF89a"), make([]byte, 64)...))
	got := ExtractVisibleStringsFromValueResult(map[string]any{"blob": encoded}, nil)
	if got.Strings != nil || got.StringPositions != nil || len(got.CardAtoms) != 1 || got.CardAtoms[0].Card != Null {
		t.Fatalf("nontext media became text or lost its barrier: %+v", got)
	}
	for _, field := range []string{"plain instruction text", "data:image/gif;base64,broken!", "%%%not-base64%%%"} {
		got := ExtractVisibleStringsFromValueResult(map[string]any{"data": field}, nil)
		if !reflect.DeepEqual(got.Strings, []string{field}) || got.IncompleteReason != "" {
			t.Fatalf("unrecognized media was hidden: %+v", got)
		}
	}
}

func TestExtractValueViewsInvalidRaw(t *testing.T) {
	for _, raw := range []string{"", "{", "{} {}", "[1,]"} {
		budget := MediaTextBudget{used: MaxMediaTextBytes, reason: mediaTextBudgetExceeded}
		if got := ExtractVisibleStringsFromJSONResultWithMediaBudget([]byte(raw), &budget); !reflect.DeepEqual(got, ExtractStringsResult{}) {
			t.Fatalf("invalid raw input %q returned %+v", raw, got)
		}
		if got := ExtractKeysFromJSONResult([]byte(raw)); !reflect.DeepEqual(got, ExtractKeysResult{}) {
			t.Fatalf("invalid raw input %q returned keys %+v", raw, got)
		}
	}
}
