// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// splitSecretToolCall builds a tools/call with n arguments of size bytes each.
// The last two argument values end and start with left and right.
func splitSecretToolCall(n, size int, left, right string) []byte {
	fields := make([]string, n)
	for i := range fields {
		value := strings.Repeat("x", size)
		switch i {
		case n - 2:
			value += left
		case n - 1:
			value = right + value
		}
		fields[i] = fmt.Sprintf(`"f%02d":%q`, i, value)
	}
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch","arguments":{` + strings.Join(fields, ",") + `}}}`)
}

func TestPairwiseSplitWorkExceeded(t *testing.T) {
	values := func(n, size int) []string {
		vals := make([]string, n, n+1)
		for i := range vals {
			vals[i] = strings.Repeat("x", size)
		}
		return append(vals, "")
	}
	// Six values of size bytes cost 2*5*6*size, so the bound falls at
	// maxPairwiseSplitWorkBytes/60 bytes each.
	atLimit := maxPairwiseSplitWorkBytes / 60
	for _, tc := range []struct {
		name string
		vals []string
		want bool
	}{
		{"five values, one large", values(pairwiseSplitUnboundedValues, 4*1024*1024), false},
		{"six values at the bound", values(6, atLimit), false},
		{"six values past the bound", values(6, atLimit+1), true},
		{"sixteen 4 KiB fields", values(19, 4*1024), false},
		{"eight 32 KiB fields", values(11, 32*1024), false},
		{"256 KiB across 56 fields", values(59, 256*1024/56), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := pairwiseSplitWorkExceeded(tc.vals); got != tc.want {
				t.Fatalf("exceeded = %v, want %v", got, tc.want)
			}
		})
	}
}

// A payload spread across many fields is refused before the pairwise scan
// runs, with the same result a call past the field cap gets. A credential
// split across two of those fields is blocked too, never passed.
func TestScanRequest_SplitSecretWorkBound(t *testing.T) {
	sc := testInputScanner(t)
	left, right := "AKIA"+"IOSFODNN", "7EXAMPLE"+"0"
	for _, tc := range []struct {
		name        string
		left, right string
	}{{"filler", "", ""}, {"split credential", left, right}} {
		t.Run(tc.name, func(t *testing.T) {
			verdict := ScanRequest(t.Context(), splitSecretToolCall(56, 256*1024/56, tc.left, tc.right), sc, config.ActionWarn, config.ActionWarn)
			if verdict.Clean || verdict.Action != config.ActionBlock || verdict.Error != "" {
				t.Fatalf("clean=%v action=%s err=%q, want block", verdict.Clean, verdict.Action, verdict.Error)
			}
			// The in-order join still names a credential it finds; otherwise
			// the call carries the refusal reason and holds before redaction.
			if tc.left != "" {
				return
			}
			if len(verdict.Matches) != 1 || verdict.Matches[0].PatternName != uninspectableSplitSecretFieldsReason {
				t.Fatalf("matches = %+v, want %q", verdict.Matches, uninspectableSplitSecretFieldsReason)
			}
			if !preRedactionBlock(verdict, config.ActionWarn) {
				t.Fatal("refusal must hold before redaction")
			}
		})
	}
}

// Calls inside the bound still run the whole pairwise scan.
func TestScanRequest_SplitSecretWorkBoundKeepsPairScan(t *testing.T) {
	sc := testInputScanner(t)
	left, right := "AKIA"+"IOSFODNN", "7EXAMPLE"+"0"
	if verdict := ScanRequest(t.Context(), splitSecretToolCall(40, 16, "", ""), sc, config.ActionWarn, config.ActionWarn); !verdict.Clean {
		t.Fatalf("forty short fields: %+v, want clean", verdict.Matches)
	}
	verdict := ScanRequest(t.Context(), splitSecretToolCall(40, 16, left, right), sc, config.ActionWarn, config.ActionWarn)
	if verdict.Clean || len(verdict.Matches) == 0 || verdict.Matches[0].PatternName == uninspectableSplitSecretFieldsReason {
		t.Fatalf("split credential in forty fields: clean=%v matches=%+v, want a credential finding", verdict.Clean, verdict.Matches)
	}
}
