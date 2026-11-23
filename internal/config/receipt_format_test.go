// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestLoadReceiptFormat(t *testing.T) {
	for _, tc := range []struct {
		name, fields, other, want, wantErr string
		useDeferDefault                    bool
	}{
		{name: "omitted"},
		{name: "null", fields: "  receipt_format: null\n"},
		{name: "blank", fields: "  receipt_format:\n"},
		{name: "explicit legacy", fields: "  receipt_format: legacy\n", want: ReceiptFormatLegacy},
		{name: "explicit v3", fields: "  receipt_format: v3\n", want: ReceiptFormatV3},
		{name: "invalid", fields: "  receipt_format: other\n", wantErr: "must be omitted, legacy, or v3"},
		{name: "multiple chains", fields: "  receipt_format: v3\n  receipt_chains: 2\n", wantErr: "requires at most one"},
		{name: "manager default", fields: "  receipt_format: v3\n", useDeferDefault: true, wantErr: "does not yet support deferred holds"},
		{name: "manager", fields: "  receipt_format: v3\n", other: "defer:\n  enabled: true\n", wantErr: "does not yet support deferred holds"},
		{name: "policy action", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  action: defer\n", wantErr: "does not yet support deferred holds"},
		{name: "policy rule", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  rules:\n    - action: defer\n", wantErr: "does not yet support deferred holds"},
		{name: "redirect rule", fields: "  receipt_format: v3\n", other: "mcp_tool_policy:\n  rules:\n    - action: redirect\n", wantErr: "does not yet support redirect rules"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			other := tc.other
			if !tc.useDeferDefault && !strings.HasPrefix(other, "defer:") {
				other += "defer:\n  enabled: false\n"
			}
			cfg, err := LoadBytes([]byte("flight_recorder:\n  enabled: true\n  dir: evidence\n  signing_key_path: signer.key\n" + tc.fields + other))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("LoadBytes error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.FlightRecorder.ReceiptFormat; got != tc.want {
				t.Fatalf("receipt format = %q, want %q", got, tc.want)
			}
		})
	}
}
