// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"strings"
	"testing"
)

func TestDLPKeywordsBundleSchemaRemainsSeparate(t *testing.T) {
	if _, err := ParseBundle([]byte(validBundleYAML())); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"keywords: [account]", "keyword_window: 50"} {
		data := strings.Replace(validBundleYAML(), "    pattern:\n", "    pattern:\n      "+field+"\n", 1)
		if _, err := ParseBundle([]byte(data)); err == nil {
			t.Fatalf("bundle accepted unsupported %s", field)
		}
	}
}
