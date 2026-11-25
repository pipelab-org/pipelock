// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestExplainEventRefusesReceiptV3(t *testing.T) {
	testreceipt.EachV3(t, func(t *testing.T, _, path string) {
		_, err := lookupExplainEvent(path, "event", explainEventSanitizer{})
		testreceipt.RequiresV3Refusal(t, err, "explain event", "the audit event reader")
	})
}
