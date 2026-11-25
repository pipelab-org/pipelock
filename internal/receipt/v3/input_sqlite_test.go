// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package v3

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestVerifierRefusesScratchDatabaseFailures(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	stream := signedStream(t, 1, nil, &Cutover{Inventory: EmptyInventoryDigest()})
	path := stream.write(t.TempDir())
	file, _ := identify(path)
	v := verification{
		ctx: ctx, store: store,
		keys: map[string]validatedKey{Digest(stream.public()): validateKey(stream.public())},
		used: map[string]bool{}, streams: map[string]*verifiedStream{},
	}
	stmt, err := store.PrepareContext(ctx, "SELECT 1")
	if err != nil {
		t.Fatal(err)
	}
	if err := stmt.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.stageFile(file, sqlRecordWriter(stmt)); err == nil || !strings.Contains(err.Error(), "stage verified record") {
		t.Fatalf("staging did not propagate the write failure: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"stage", func() error { return v.stageFiles([]inputFile{file}) }},
		{"appraise", v.appraiseDecisions},
		{"predecessor", func() error {
			parent := &verifiedStream{limit: maxInteger}
			child := &verifiedStream{body: StreamOpen{Previous: &Previous{Stream: stream.id}}}
			return v.checkPin(parent, child)
		}},
		{"broken stream", v.verifyStreams},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err == nil {
				t.Fatal("verification used a closed scratch database")
			}
		})
	}
}

func TestAppraisalRefusesMissingDecisionIndex(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.ExecContext(ctx, "DROP TABLE decision_ids"); err != nil {
		t.Fatal(err)
	}
	v := verification{ctx: ctx, store: store}
	if err := v.appraiseDecisions(); err == nil || !strings.Contains(err.Error(), "prepare decision index") ||
		!strings.Contains(err.Error(), "no such table: decision_ids") {
		t.Fatalf("decision appraisal error = %v, want missing index diagnostic", err)
	}
}

func TestWalkRecordsRefusesMalformedScratchRows(t *testing.T) {
	for _, tc := range []struct {
		name             string
		payload, unknown string
	}{
		{"column type", "{}", "unreadable"},
		{"payload", "{", "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := newStore(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer store.close()
			const insert = "INSERT INTO records (stream,seq,id,payload,unknown,body_code) VALUES (?,0,'record',?,?, '')"
			if _, err := store.ExecContext(t.Context(), insert, "stream", tc.payload, tc.unknown); err != nil {
				t.Fatal(err)
			}
			err = walkRecords(t.Context(), store, "stream", maxInteger, func(stagedRecord) error {
				t.Fatal("passed a corrupt record to verification")
				return nil
			})
			if err == nil {
				t.Fatal("bad scratch data produced no error")
			}
		})
	}
}

func TestScratchDirectoryCreationFailure(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "missing")
	if _, err := newStoreIn(t.Context(), parent); err == nil || !strings.Contains(err.Error(), "scratch directory") {
		t.Fatalf("unexpected scratch-directory result: %v", err)
	}
}

func TestScratchInitializationCancellationRemovesDirectory(t *testing.T) {
	parent := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if store, err := newStoreIn(ctx, parent); !errors.Is(err, context.Canceled) || store != nil {
		t.Fatalf("canceled scratch initialization: %v", err)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("failed initialization left a scratch directory")
	}
}

func TestRecordStagingRefusesMissingTable(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	if _, err := store.ExecContext(ctx, "DROP TABLE records"); err != nil {
		t.Fatal(err)
	}
	err = store.stage(ctx, func(recordWriter) error {
		t.Error("staging proceeded without its scratch table")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "prepare record staging") {
		t.Fatalf("staging error = %v, want scratch table preparation failure", err)
	}
}
