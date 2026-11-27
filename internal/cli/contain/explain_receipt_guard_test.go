// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

func TestFindEgressBlockEventRefusesLaterReceipt(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	data := []byte("{\"id\":\"event-1\"}\n" + evidencename.ReceiptProfilePrefix + "v3\"}\n")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := findEgressBlockEvent(file, "event-1")
	if !errors.Is(err, evidencename.ErrReceiptProfile) {
		t.Fatalf("findEgressBlockEvent() error = %v, want receipt refusal", err)
	}
}

func TestFindEgressBlockEventKeepsFirstMatch(t *testing.T) {
	file := filepath.Join(t.TempDir(), "events.jsonl")
	data := []byte("{\"id\":\"event-1\",\"class\":\"first\"}\n{\"id\":\"event-1\",\"class\":\"second\"}\n")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	event, err := findEgressBlockEvent(file, "event-1")
	if err != nil || event.Class != "first" {
		t.Fatalf("event = %+v, error = %v", event, err)
	}
}
