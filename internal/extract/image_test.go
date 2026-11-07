// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package extract

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testimage"
)

func TestDLPImageViewPreservesGenericExtraction(t *testing.T) {
	payload := testimage.SmallPNG(t, "")
	raw := []byte(testimage.Carrier(t, "anthropic", "png", payload))
	encoded := base64.StdEncoding.EncodeToString(payload)
	generic := AllStringsFromJSONResult(raw)
	scanned := AllDLPStringsFromJSONResult(raw)
	found := false
	for i, text := range generic.Strings {
		if text != encoded {
			continue
		}
		found = true
		if !strings.HasPrefix(scanned.Strings[i], "data:image/png;base64,") {
			t.Fatal("scan view lost media declaration")
		}
	}
	if !found {
		t.Fatal("generic extraction changed the image value")
	}
	if len(generic.Strings) != len(scanned.Strings) || generic.Truncated || scanned.Truncated {
		t.Fatal("scan view changed extraction shape")
	}
}
