// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

// opaqueRunFloorSentence is the configuration reference's statement of the
// shortest printable run scanned inside an opaque response body.
var opaqueRunFloorSentence = regexp.MustCompile(`maximal contiguous printable runs of at least (\d+) bytes`)

// The published opaque-run floor and binaryResponseTextRunMinBytes must agree,
// so changing either one alone fails here instead of drifting silently.
func TestOpaqueRunFloorMatchesConfigurationReference(t *testing.T) {
	doc, err := os.ReadFile("../../docs/configuration.md")
	if err != nil {
		t.Fatal(err)
	}
	matches := opaqueRunFloorSentence.FindAllSubmatch(doc, -1)
	if len(matches) != 1 {
		t.Fatalf("configuration reference states the opaque-run floor %d times, want exactly once", len(matches))
	}
	published, err := strconv.Atoi(string(matches[0][1]))
	if err != nil {
		t.Fatal(err)
	}
	if published != binaryResponseTextRunMinBytes {
		t.Fatalf("docs/configuration.md publishes a %d-byte opaque run floor, code uses binaryResponseTextRunMinBytes = %d", published, binaryResponseTextRunMinBytes)
	}
}
