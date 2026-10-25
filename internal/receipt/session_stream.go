// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"errors"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// WalkReceiptsFromSessionDir reads receipts in the same order and under the
// same extraction policy as ExtractReceiptsFromSessionDir, retaining no chain.
// The callback must not retain receipts if it needs bounded memory.
func WalkReceiptsFromSessionDir(dir, sessionID string, consume func(Receipt) error) error {
	if consume == nil {
		return errors.New("session receipt consumer is required")
	}
	return recorder.WalkSessionHistory(dir, sessionID, func(e recorder.Entry) error {
		r, ok, err := receiptFromChainEntry(e)
		if err != nil || !ok {
			return err
		}
		return consume(r)
	})
}

// WalkReceiptsFromSessionDirPrefix applies extraction policy over a complete
// writer-observed prefix while allowing later appends. The caller must verify
// the receipt chain and bind its final head to the writer's observation.
func WalkReceiptsFromSessionDirPrefix(dir, sessionID string, prefix recorder.SessionHistoryPrefix, consume func(Receipt) error) error {
	if consume == nil {
		return errors.New("session receipt consumer is required")
	}
	return recorder.WalkSessionHistoryPrefix(dir, sessionID, prefix, func(e recorder.Entry) error {
		r, ok, err := receiptFromChainEntry(e)
		if err != nil || !ok {
			return err
		}
		return consume(r)
	})
}
