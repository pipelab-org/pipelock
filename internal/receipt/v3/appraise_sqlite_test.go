// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package v3

import (
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
)

func TestDecisionIndexUsesPreparedLookup(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	index := decisionIndex{ctx: ctx, tx: tx, disk: true}
	if err := index.prepare(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := index.remember("example", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := index.rememberID.Close(); err != nil {
		t.Fatal(err)
	}
	if err := index.remember("example", true); err == nil {
		t.Fatal("remember succeeded after closing its prepared statement")
	}
}

func TestDecisionIndexRejectsUnusableTransaction(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	index := &decisionIndex{ctx: ctx, tx: tx, disk: true}
	if err := index.prepare(); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := index.prepare(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("want closed transaction error from preparation, got %v", err)
	}
	for _, tc := range []struct {
		name  string
		check func() error
	}{
		{"reset", index.reset},
		{"remember", func() error { return index.remember("decision", true) }},
		{"opaque", func() error { _, err := index.opaque("decision"); return err }},
		{"begin", index.beginSegment},
		{"get", func() error { _, err := index.get("decision"); return err }},
		{"put", func() error { return index.put("decision", pieceEntry{}) }},
		{"each", func() error { return index.eachPiece(func(pieceEntry) {}) }},
		{"shape", func() error { _, err := index.badShape(0, "decision"); return err }},
		{"hold", func() error { _, err := index.holdOwner("hold", "decision"); return err }},
		{"walk", func() error {
			return walkRecords(ctx, tx, "stream", maxInteger, func(stagedRecord) error { return nil })
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.check(); err == nil {
				t.Fatal("operation succeeded after rollback")
			}
		})
	}
	if _, err := decodePiece([]byte("[")); err == nil {
		t.Fatal("accepted corrupt decision state")
	}
}

func TestDecisionIndexRefusesMalformedPiece(t *testing.T) {
	ctx := t.Context()
	store, err := newStore(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	tx, err := store.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := tx.Rollback(); err != nil {
			t.Error(err)
		}
	}()
	if _, err := tx.ExecContext(ctx, "INSERT INTO decision_pieces VALUES (?, ?)", "decision", []byte("{")); err != nil {
		t.Fatal(err)
	}
	index := decisionIndex{ctx: ctx, tx: tx, disk: true}
	err = index.eachPiece(func(pieceEntry) { t.Error("appraised a malformed decision piece") })
	var syntax *json.SyntaxError
	if !errors.As(err, &syntax) {
		t.Fatalf("iterate malformed decision piece: got %v, want a JSON syntax error", err)
	}
}
