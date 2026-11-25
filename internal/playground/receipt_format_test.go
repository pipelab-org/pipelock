// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package playground

import (
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestAssembleRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		for _, input := range []string{dir, path} {
			_, err := AssembleFromEvidence(input, "", t.TempDir(), time.Time{})
			testreceipt.RequiresV3Refusal(t, err, "playground assemble", "the playground")
		}
	})
}
