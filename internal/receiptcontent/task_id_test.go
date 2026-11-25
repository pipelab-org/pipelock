// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receiptcontent

import (
	"strings"
	"testing"
)

func TestTaskOriginProjection(t *testing.T) {
	p := &Producer{schema: &Schema{Kind: "test.task-origin", Fields: map[string]Class{"task": ProvenTaskID}}}
	id := NewGeneratedID().String()
	last := "0"
	if strings.HasSuffix(id, last) {
		last = "1"
	}
	tampered := id[:len(id)-1] + last
	for _, tc := range []struct {
		value    string
		excluded bool
	}{{TaskIDPrefix + id, true}, {TaskIDPrefix + tampered, false}, {id, false}, {TaskIDPrefix + "00000000-0000-7000-8000-000000000000", false}, {"task-invalid", false}} {
		proj, err := p.Project([]byte(`{"task":"` + tc.value + `"}`))
		if err != nil {
			t.Fatal(err)
		}
		a, found := atomPaths(proj)["task"]
		if found == tc.excluded {
			t.Fatalf("projected=%v want excluded=%v", found, tc.excluded)
		}
		if found && !a.Identity {
			t.Fatal("unproven task must remain identity")
		}
	}
}
