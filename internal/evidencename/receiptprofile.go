// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package evidencename

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
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
	return bytes.HasPrefix(bytes.TrimLeftFunc(data, unicode.IsSpace), []byte(ReceiptProfilePrefix))
}

// ErrReceiptProfile marks evidence that requires the receipt-profile verifier.
var ErrReceiptProfile = errors.New("receipt v3 evidence is not supported")

// UnsupportedReceiptProfile adds verifier guidance for the input scope.
func UnsupportedReceiptProfile(directory bool) error {
	verify := "pipelock verify-receipt <path>"
	if directory {
		verify = "pipelock verify-receipt --chain <path>"
	}
	return fmt.Errorf("%w by this reader; use '%s'", ErrReceiptProfile, verify)
}

// ClaimsReceiptName reserves profile stream names ("*.receipt-vN.jsonl").
// Cutover inventories are not claimed on their own because the cutover only
// commits when the first v3 stream file is published.
func ClaimsReceiptName(name string) bool {
	_, stream := ReceiptProfileVersion(name)
	return stream
}

// ReceiptProfileEntry finds the first profile-shaped non-directory entry.
// Other non-regular entries remain claimed so readers cannot follow them as legacy evidence.
func ReceiptProfileEntry(entries []fs.DirEntry) string {
	for _, entry := range entries {
		if !entry.IsDir() && ClaimsReceiptName(entry.Name()) {
			return entry.Name()
		}
	}
	return ""
}

// RefuseReceiptName checks the name of a file a legacy reader would open.
func RefuseReceiptName(path string) error {
	if ClaimsReceiptName(filepath.Base(filepath.Clean(path))) {
		return fmt.Errorf("%q: %w", path, UnsupportedReceiptProfile(false))
	}
	return nil
}

// RefuseReceiptContent checks a record before a legacy decoder interprets it.
func RefuseReceiptContent(data []byte) error {
	if ClaimsReceiptContent(data) {
		return UnsupportedReceiptProfile(false)
	}
	return nil
}

// SplitLegacyJSONLines detects receipt profiles even when a record exceeds the
// scanner buffer, as soon as its identifying prefix is available.
func SplitLegacyJSONLines(data []byte, atEOF bool) (int, []byte, error) {
	advance, line, err := bufio.ScanLines(data, atEOF)
	probe := line
	if probe == nil {
		probe = data
	}
	if claimErr := RefuseReceiptContent(probe); claimErr != nil {
		return 0, nil, claimErr
	}
	return advance, line, err
}

// ProbeReceiptContent reads the identifying prefix after at most 64 KiB of
// leading whitespace. Record size and content still belong to the decoder.
func ProbeReceiptContent(r io.Reader) (bool, error) {
	const maxLeadingWhitespace = 64 << 10
	input := bufio.NewReader(io.LimitReader(r, int64(maxLeadingWhitespace+len(ReceiptProfilePrefix))))
	leadingWhitespace := 0
	for {
		ch, size, err := input.ReadRune()
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if unicode.IsSpace(ch) {
			leadingWhitespace += size
			if leadingWhitespace > maxLeadingWhitespace {
				return false, nil
			}
			continue
		}
		if err := input.UnreadRune(); err != nil {
			return false, err
		}
		break
	}
	var prefix [len(ReceiptProfilePrefix)]byte
	if _, err := io.ReadFull(input, prefix[:]); errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return ClaimsReceiptContent(prefix[:]), nil
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
