// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// IsBareEvidenceSession recognizes receipt-only compatibility input.
func IsBareEvidenceSession(location recorder.EvidenceLocation, session string) (bool, error) {
	names, err := BareEvidenceSessionShards(location, session)
	return len(names) > 0, err
}

// BareEvidenceSessionShards lists the shards read from a receipt-only
// compatibility session. Recorder metadata or mixed entries return no list.
func BareEvidenceSessionShards(location recorder.EvidenceLocation, session string) ([]string, error) {
	notBare := errors.New("not a bare evidence receipt session")
	seen := false
	var names []string
	err := recorder.WalkSessionHistoryFiles(location, session, func(shard recorder.SessionHistoryShard, r io.Reader) error {
		names = append(names, shard.Name)
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, 0, 64<<10), 10<<20)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			// A map collapses duplicate keys and accepts a null detail, so
			// either one could pass for a two-field receipt line. Both route
			// to full recorder verification instead.
			if jsonscan.RejectDuplicateKeys(line) != nil {
				return notBare
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(line, &fields) != nil || len(fields) != 2 || !bytes.HasPrefix(fields["detail"], []byte("{")) {
				return notBare
			}
			var kind string
			if json.Unmarshal(fields["type"], &kind) != nil || kind != contractreceipt.EvidenceEntryType {
				return notBare
			}
			seen = true
		}
		return scanner.Err()
	})
	if errors.Is(err, notBare) {
		return nil, nil
	}
	if err != nil || !seen {
		return nil, err
	}
	return names, nil
}
