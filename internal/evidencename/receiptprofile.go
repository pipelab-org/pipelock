// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidencename

import (
	"bytes"
	"regexp"
	"strings"
)

// ReceiptProfilePrefix opens every receipt-profile record. A file or payload
// that starts with it is claimed by the receipt-profile verifier, whatever it
// is named.
const ReceiptProfilePrefix = "{\"payloadType\":\"application/vnd.pipelock.receipt."

const (
	cutoverPrefix = "receipt-v3-cutover-"
	cutoverSuffix = ".json"
	groupPrefix   = "receipt-group-"
	groupSuffix   = ".json"
)

var profileName = regexp.MustCompile(`\.receipt-v([0-9]+)\.jsonl$`)

// ReceiptProfileVersion returns the digits of a "*.receipt-vN.jsonl" name,
// whatever N is, so a later profile is claimed the same way v3 is.
func ReceiptProfileVersion(name string) (version string, ok bool) {
	match := profileName.FindStringSubmatch(name)
	if match == nil {
		return "", false
	}
	return match[1], true
}

// ClaimsReceiptContent reports whether data begins with the receipt-profile
// prefix.
func ClaimsReceiptContent(data []byte) bool {
	return bytes.HasPrefix(data, []byte(ReceiptProfilePrefix))
}

// CutoverInventoryHash returns the 64-digit lowercase hash of a
// "receipt-v3-cutover-<hash>.json" inventory name.
func CutoverInventoryHash(name string) (hash string, ok bool) {
	tail, prefixed := strings.CutPrefix(name, cutoverPrefix)
	hash, suffixed := strings.CutSuffix(tail, cutoverSuffix)
	return hash, prefixed && suffixed && isLowerHex(hash, 64)
}

// IsReceiptGroupArtifact reports whether name is a receipt-group file.
func IsReceiptGroupArtifact(name string) bool {
	return strings.HasPrefix(name, groupPrefix) && strings.HasSuffix(name, groupSuffix)
}

// IsLegacyReceiptCandidate reports whether name is a legacy receipt file whose
// content a receipt-profile reader must still inspect before trusting the name:
// a recorder shard, a receipt group, or one of the ceremony receipt logs.
func IsLegacyReceiptCandidate(name string) bool {
	_, _, isShard := Parse(name)
	return isShard || IsReceiptGroupArtifact(name) || name == "activation-receipts.jsonl" ||
		name == "redaction-receipts.jsonl" || name == "ratification-receipts.jsonl"
}

func isLowerHex(text string, width int) bool {
	if len(text) != width {
		return false
	}
	for i := range len(text) {
		if ch := text[i]; (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}
