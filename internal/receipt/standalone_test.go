// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package receipt

import "testing"

func TestIsStandaloneEvidenceReceipt(t *testing.T) {
	for _, tt := range []struct {
		name   string
		input  string
		wantV2 bool
		err    string
	}{
		{name: "invalid JSON", input: "{", err: "invalid receipt JSON: unexpected end of JSON input"},
		{name: "ambiguous record type", input: `{"version":1,"record_type":"evidence_receipt_v2"}`, err: "ambiguous receipt format: version conflicts with record_type or receipt_version"},
		{name: "ambiguous receipt version", input: `{"version":1,"receipt_version":2}`, err: "ambiguous receipt format: version conflicts with record_type or receipt_version"},
		{name: "string version", input: `{"version":"1"}`, err: "receipt version must be an integer: json: cannot unmarshal string into Go value of type int"},
		{name: "null version", input: `{"version":null}`, err: "receipt version must be an integer"},
		{name: "unknown version", input: `{"version":2}`, err: "unsupported receipt version 2 (expected 1)"},
		{name: "boolean record type", input: `{"record_type":true}`, err: "receipt record_type must be a string: json: cannot unmarshal bool into Go value of type receipt.RecordType"},
		{name: "null record type", input: `{"record_type":null}`, err: "receipt record_type must be a string"},
		{name: "unknown record type", input: `{"record_type":"future"}`, err: `unsupported receipt record_type "future"`},
		{name: "missing receipt version", input: `{"record_type":"evidence_receipt_v2"}`, err: "EvidenceReceipt v2 requires receipt_version"},
		{name: "string receipt version", input: `{"record_type":"evidence_receipt_v2","receipt_version":"2"}`, err: "receipt_version must be an integer: json: cannot unmarshal string into Go value of type int"},
		{name: "null receipt version", input: `{"record_type":"evidence_receipt_v2","receipt_version":null}`, err: "receipt_version must be an integer"},
		{name: "wrong receipt version", input: `{"record_type":"evidence_receipt_v2","receipt_version":1}`, err: "EvidenceReceipt requires receipt_version=2: got 1"},
		{name: "missing discriminator", input: `{"Version":1}`, err: "missing receipt format discriminator: expected version or record_type"},
		{name: "unsafe number", input: `{"version":1,"value":1e999}`, err: `invalid JSON number "1e999": strconv.ParseFloat: parsing "1e999": value out of range`},
		{name: "v1", input: `{"version":1}`},
		{name: "v2", input: `{"record_type":"evidence_receipt_v2","receipt_version":2}`, wantV2: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsStandaloneEvidenceReceipt([]byte(tt.input))
			var errText string
			if err != nil {
				errText = err.Error()
			}
			if got != tt.wantV2 || errText != tt.err {
				t.Fatalf("IsStandaloneEvidenceReceipt = %t, %q, want %t, %q", got, errText, tt.wantV2, tt.err)
			}
		})
	}
}
