// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

//go:build !js || !wasm

package v3

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type recordStore struct {
	*sql.DB
	dir string
}

func newStore(ctx context.Context) (*recordStore, error) {
	return newStoreIn(ctx, "")
}

func newStoreIn(ctx context.Context, parent string) (*recordStore, error) {
	dir, err := os.MkdirTemp(parent, "pipelock-v3-verify-")
	if err != nil {
		return nil, fmt.Errorf("create verification scratch directory: %w", err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "verify.db"))
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("open verification scratch database: %w", err)
	}
	s := &recordStore{db, dir}
	const schema = `
PRAGMA journal_mode=OFF;
CREATE TABLE records (
	stream TEXT NOT NULL, seq INTEGER NOT NULL, id TEXT NOT NULL,
	payload BLOB NOT NULL, unknown INTEGER NOT NULL, body_code TEXT NOT NULL, after_damage INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (stream, seq, id)
) WITHOUT ROWID;
CREATE TABLE decision_ids (
	id TEXT PRIMARY KEY, opaque INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE decision_pieces (
	id TEXT PRIMARY KEY, state BLOB NOT NULL
) WITHOUT ROWID;
CREATE TABLE bad_shapes (
	segment INTEGER NOT NULL, id TEXT NOT NULL, PRIMARY KEY (segment,id)
) WITHOUT ROWID;
CREATE TABLE hold_owners (
	id TEXT PRIMARY KEY, action_id TEXT NOT NULL
) WITHOUT ROWID;`
	if _, err := s.ExecContext(ctx, schema); err != nil {
		s.close()
		return nil, fmt.Errorf("initialize verification scratch database: %w", err)
	}
	return s, nil
}

func (s *recordStore) close() {
	_ = s.Close()
	_ = os.RemoveAll(s.dir)
}

type recordQuery interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func walkRecords(ctx context.Context, source recordQuery, stream string, end int64, apply func(stagedRecord) error) error {
	rows, err := source.QueryContext(ctx, "SELECT id, payload, unknown, body_code, after_damage FROM records WHERE stream=? AND seq<=? ORDER BY seq,id", stream, end)
	if err != nil {
		return fmt.Errorf("query verified stream records: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var record stagedRecord
		var payload []byte
		if err := rows.Scan(&record.id, &payload, &record.unknown, &record.bodyCode, &record.afterDamage); err != nil {
			return fmt.Errorf("read verified stream record: %w", err)
		}
		if err := json.Unmarshal(payload, &record.Common); err != nil {
			return fmt.Errorf("decode verified stream record: %w", err)
		}
		if err := apply(record); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate verified stream records: %w", err)
	}
	return nil
}

func (s *recordStore) stage(ctx context.Context, apply func(recordWriter) error) error {
	tx, err := s.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("start record staging: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	const insert = `INSERT INTO records (stream,seq,id,payload,unknown,body_code,after_damage) VALUES (?,?,?,?,?,?,?)
ON CONFLICT (stream,seq,id) DO UPDATE SET after_damage = min(after_damage,excluded.after_damage)`
	stmt, err := tx.PrepareContext(ctx, insert)
	if err != nil {
		return fmt.Errorf("prepare record staging: %w", err)
	}
	defer func() { _ = stmt.Close() }()
	if err := apply(sqlRecordWriter(stmt)); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit staged records: %w", err)
	}
	return nil
}

func sqlRecordWriter(stmt *sql.Stmt) recordWriter {
	return func(ctx context.Context, item stagedRecord, payload []byte) error {
		_, err := stmt.ExecContext(ctx, item.Stream, item.Seq, item.id, payload, item.unknown, item.bodyCode, item.afterDamage)
		return err
	}
}

func (s *recordStore) walk(ctx context.Context, stream string, end int64, apply func(stagedRecord) error) error {
	return walkRecords(ctx, s, stream, end, apply)
}

func (s *recordStore) pin(ctx context.Context, stream string, seq, limit int64) (string, string, error) {
	var id, kind string
	err := s.QueryRowContext(ctx,
		"SELECT id, json_extract(payload, '$.kind') FROM records WHERE stream=? AND seq=? AND seq<=?",
		stream, seq, limit).Scan(&id, &kind)
	return id, kind, err
}

func (s *recordStore) beginAppraisal() (*sql.Tx, error) {
	// The transaction's bounded index lookups don't each need a cancellation goroutine.
	return s.BeginTx(context.Background(), nil)
}

func (*recordStore) walkAppraisal(ctx context.Context, tx *sql.Tx, stream string, end int64, apply func(stagedRecord) error) error {
	return walkRecords(ctx, tx, stream, end, apply)
}
