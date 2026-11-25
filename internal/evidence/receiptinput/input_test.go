// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receiptinput_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/evidence/receiptinput"
	"github.com/luckyPipewrench/pipelock/internal/testreceipt"
)

func TestReceiptInputRefusal(t *testing.T) {
	const command, reader = "example", "the example reader"
	path := filepath.Join(t.TempDir(), "legacy.jsonl")
	if err := receiptinput.Refuse(path, command, reader); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing input: %v", err)
	}
	legacy := []byte("{\"record_type\":\"action_receipt\"}\n")
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{path, filepath.Dir(path)} {
		if err := receiptinput.Refuse(target, command, reader); err != nil {
			t.Fatalf("legacy input %s: %v", target, err)
		}
	}
	if claimed, err := receiptinput.Claims(path); claimed || err != nil {
		t.Fatalf("legacy claim: %t, %v", claimed, err)
	}
	if err := receiptinput.RefusePayload(legacy, command, reader); err != nil {
		t.Fatal(err)
	}
	testreceipt.EachV3(t, func(t *testing.T, dir, path string) {
		if claimed, err := receiptinput.Claims(dir); !claimed || err != nil {
			t.Fatalf("v3 directory claim: %t, %v", claimed, err)
		}
		err := receiptinput.Refuse(dir, command, reader)
		testreceipt.RequiresV3Refusal(t, err, command, reader)
		if !strings.Contains(err.Error(), "verify-receipt --chain") {
			t.Fatalf("directory instruction: %v", err)
		}
		err = receiptinput.Refuse(path, command, reader)
		testreceipt.RequiresV3Refusal(t, err, command, reader)
		if strings.Contains(err.Error(), "--chain") {
			t.Fatalf("file instruction: %v", err)
		}
	})
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	testreceipt.RequiresV3Refusal(t, receiptinput.Refuse(path, command, reader), command, reader)
	testreceipt.RequiresV3Refusal(t, receiptinput.RefusePayload(data, command, reader), command, reader)
	testreceipt.RequiresV3Refusal(t, receiptinput.RefusePayload(append([]byte("\n"), data...), command, reader), command, reader)
	testreceipt.RequiresV3Refusal(t, receiptinput.RefusePayload(append(append([]byte{}, legacy...), data...), command, reader), command, reader)
	testreceipt.RequiresV3Refusal(t, receiptinput.UnsupportedDirectory(command, reader), command, reader)
}

func TestReceiptInputRefuseTreeAndLocation(t *testing.T) {
	const command, reader = "example", "the example reader"
	root := t.TempDir()
	sub := filepath.Join(root, "nested")
	if err := os.Mkdir(sub, 0o750); err != nil {
		t.Fatal(err)
	}
	testreceipt.V3(t, sub, false)
	testreceipt.RequiresV3Refusal(t, receiptinput.RefuseTree(root, command, reader), command, reader)
	if err := os.WriteFile(filepath.Join(sub, "evidence-proxy-0.jsonl"), []byte{}, 0o600); err != nil {
		t.Fatal(err)
	}
	testreceipt.RequiresV3Refusal(t, receiptinput.RefuseLocation(root, command, reader), command, reader)
}

func TestReceiptInputRefuseLocationMultiLocationRenamedV3(t *testing.T) {
	const command, reader = "example", "the example reader"
	v3File, _ := testreceipt.V3(t, t.TempDir(), false)
	v3Data, err := os.ReadFile(filepath.Clean(v3File))
	if err != nil {
		t.Fatal(err)
	}
	legacy := []byte("{\"record_type\":\"action_receipt\"}\n")

	t.Run("root legacy plus child renamed v3", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "evidence-proxy-0.jsonl"), legacy, 0o600); err != nil {
			t.Fatal(err)
		}
		child := filepath.Join(root, "child")
		if err := os.Mkdir(child, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(child, "evidence-proxy-0.jsonl"), append([]byte("\n  "), v3Data...), 0o600); err != nil {
			t.Fatal(err)
		}
		testreceipt.RequiresV3Refusal(t, receiptinput.RefuseLocation(root, command, reader), command, reader)
	})

	t.Run("two sibling locations one with renamed v3", func(t *testing.T) {
		root := t.TempDir()
		dirA := filepath.Join(root, "a")
		dirB := filepath.Join(root, "b")
		for _, dir := range []string{dirA, dirB} {
			if err := os.Mkdir(dir, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(dirA, "evidence-proxy-0.jsonl"), legacy, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dirB, "evidence-proxy-0.jsonl"), v3Data, 0o600); err != nil {
			t.Fatal(err)
		}
		testreceipt.RequiresV3Refusal(t, receiptinput.RefuseLocation(root, command, reader), command, reader)
	})
}
