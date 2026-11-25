// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package shadow

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
)

func TestGeneratedEventOrigin(t *testing.T) {
	id, err := newEventID()
	if err != nil {
		t.Fatal(err)
	}
	if !receiptcontent.VerifyGeneratedID(id) {
		t.Fatal("generated event lacks origin proof")
	}
}
