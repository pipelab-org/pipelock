// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func TestDecodedTextDLPViewsParity(t *testing.T) {
	for _, text := range []string{"ordinary text", "UEsDBA==", base64.StdEncoding.EncodeToString([]byte("PK\x03\x04example")), "%50%4b%03%04"} {
		t.Run(text, func(t *testing.T) {
			want := decodeEncodingsFixpoint(text, true)
			got := DecodedTextDLPViews(text)
			var texts []string
			for _, d := range want {
				texts = append(texts, d.text)
			}
			if len(got) == 0 && len(texts) == 0 {
				return
			}
			if !reflect.DeepEqual(got, texts) {
				t.Fatalf("decoded view admission differs: got %q want %q", got, texts)
			}
		})
	}
}
