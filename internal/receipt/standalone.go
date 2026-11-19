// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"errors"
	"fmt"

	contractreceipt "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

// IsStandaloneEvidenceReceipt identifies the format of a bare receipt file.
// It uses exact top-level discriminator names. The selected parser then enforces
// its own full schema, including duplicate keys and case aliases.
func IsStandaloneEvidenceReceipt(data []byte) (bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return false, fmt.Errorf("invalid receipt JSON: %w", err)
	}
	if err := jsonscan.RejectUnsafeNumbers(data); err != nil {
		return false, err
	}
	version, hasVersion := fields["version"]
	recordType, hasRecordType := fields["record_type"]
	receiptVersion, hasReceiptVersion := fields["receipt_version"]
	switch {
	case hasVersion && (hasRecordType || hasReceiptVersion):
		return false, errors.New("ambiguous receipt format: version conflicts with record_type or receipt_version")
	case hasVersion:
		var v *int
		if err := json.Unmarshal(version, &v); err != nil {
			return false, fmt.Errorf("receipt version must be an integer: %w", err)
		}
		if v == nil {
			return false, errors.New("receipt version must be an integer")
		}
		if *v != ReceiptVersion {
			return false, fmt.Errorf("unsupported receipt version %d (expected %d)", *v, ReceiptVersion)
		}
		return false, nil
	case hasRecordType:
		var kind *contractreceipt.RecordType
		if err := json.Unmarshal(recordType, &kind); err != nil {
			return false, fmt.Errorf("receipt record_type must be a string: %w", err)
		}
		if kind == nil {
			return false, errors.New("receipt record_type must be a string")
		}
		if *kind != contractreceipt.RecordTypeEvidenceV2 {
			return false, fmt.Errorf("unsupported receipt record_type %q", *kind)
		}
		if !hasReceiptVersion {
			return false, errors.New("EvidenceReceipt v2 requires receipt_version")
		}
		var v *int
		if err := json.Unmarshal(receiptVersion, &v); err != nil {
			return false, fmt.Errorf("receipt_version must be an integer: %w", err)
		}
		if v == nil {
			return false, errors.New("receipt_version must be an integer")
		}
		if *v != 2 {
			return false, fmt.Errorf("%w: got %d", contractreceipt.ErrWrongReceiptVersion, *v)
		}
		return true, nil
	default:
		return false, errors.New("missing receipt format discriminator: expected version or record_type")
	}
}
