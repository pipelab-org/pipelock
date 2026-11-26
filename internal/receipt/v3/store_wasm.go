// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package v3

import (
	"cmp"
	"context"
	"database/sql"
	"slices"
)

type recordKey struct {
	seq int64
	id  string
}

type recordStore struct {
	records map[string]map[recordKey]stagedRecord
	order   map[string][]recordKey
}

func newStore(context.Context) (*recordStore, error) {
	return &recordStore{
		records: make(map[string]map[recordKey]stagedRecord),
		order:   make(map[string][]recordKey),
	}, nil
}

func (*recordStore) close() {}

func (s *recordStore) stage(ctx context.Context, apply func(recordWriter) error) error {
	if err := apply(s.write); err != nil {
		return err
	}
	for _, order := range s.order {
		slices.SortFunc(order, func(a, b recordKey) int {
			return cmp.Or(cmp.Compare(a.seq, b.seq), cmp.Compare(a.id, b.id))
		})
	}
	return ctx.Err()
}

func (s *recordStore) write(ctx context.Context, item stagedRecord, _ []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	rows := s.records[item.Stream]
	if rows == nil {
		rows = make(map[recordKey]stagedRecord)
		s.records[item.Stream] = rows
	}
	key := recordKey{item.Seq, item.id}
	if previous, exists := rows[key]; exists {
		previous.afterDamage = previous.afterDamage && item.afterDamage
		rows[key] = previous
	} else {
		rows[key] = item
		s.order[item.Stream] = append(s.order[item.Stream], key)
	}
	return nil
}

func (s *recordStore) walk(ctx context.Context, stream string, end int64, apply func(stagedRecord) error) error {
	for _, key := range s.order[stream] {
		if key.seq > end {
			break
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := apply(s.records[stream][key]); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (s *recordStore) pin(ctx context.Context, stream string, seq, limit int64) (string, string, error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	order := s.order[stream]
	i, found := slices.BinarySearchFunc(order, seq, func(key recordKey, seq int64) int {
		return cmp.Compare(key.seq, seq)
	})
	if seq > limit || !found {
		return "", "", sql.ErrNoRows
	}
	item := s.records[stream][order[i]]
	return item.id, item.Kind, nil
}

func (*recordStore) beginAppraisal() (*sql.Tx, error) { return nil, nil }

func (s *recordStore) walkAppraisal(ctx context.Context, _ *sql.Tx, stream string, end int64, apply func(stagedRecord) error) error {
	return s.walk(ctx, stream, end, apply)
}
