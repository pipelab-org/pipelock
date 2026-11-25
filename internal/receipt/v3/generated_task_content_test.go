// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
	"github.com/luckyPipewrench/pipelock/internal/session"
)

func TestGeneratedTaskIdentityContent(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	for _, tc := range []struct {
		id       string
		excluded bool
	}{{session.NextTaskID(), true}, {"task-01a21164-8b37-7afc-8197-" + "191445742490", false}} {
		p, err := actionProjection.Project([]byte(`{"session":{"task_id":"` + tc.id + `"}}`))
		if err != nil {
			t.Fatal(err)
		}
		found := strings.Contains(string(p.Structured()), tc.id)
		if found == tc.excluded {
			t.Fatalf("task projected=%v want excluded=%v", found, tc.excluded)
		}
		rep, err := receiptcontent.Scan(t.Context(), sc.ScanTextForReceiptDLP, p)
		if err != nil {
			t.Fatal(err)
		}
		if rep.Clean() != tc.excluded {
			t.Fatalf("task clean=%v want=%v", rep.Clean(), tc.excluded)
		}
	}
}
