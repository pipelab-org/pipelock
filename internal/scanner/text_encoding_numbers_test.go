// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTextEncodingBinaryNumberAdmission(t *testing.T) {
	// Base64 decoding repeated 4141 produces repeated binary bytes with an
	// isolated digit. Those digits are not a textual character-code list.
	binary, _ := base64.StdEncoding.DecodeString(strings.Repeat("4141", 16))
	for _, view := range appendTextEncodingViews(nil, string(binary)) {
		if view.encoding == encodingDecimal {
			t.Fatal("binary bytes admitted as a character-code list")
		}
	}
	// Controls in the decoded value must not hide an otherwise textual carrier.
	key := "xoxb-" + "1234567890abcdef"
	encoded := decimalCharacterCodes("\x00"+key+"\x00", " ")
	found := false
	for _, view := range appendTextEncodingViews(nil, encoded) {
		if strings.Contains(view.text, key) {
			found = true
		}
	}
	if !found {
		t.Fatal("textual character-code list lost its protected value")
	}
}

func TestTextEncodingQuotedPrintableTextAdmission(t *testing.T) {
	for _, view := range appendTextEncodingViews(nil, string([]byte{0xff})+"=41") {
		if view.encoding == encodingQuotedPrintable {
			t.Fatal("binary bytes admitted as quoted-printable text")
		}
	}
	found := false
	for _, view := range appendTextEncodingViews(nil, "café =41") {
		if view.encoding == encodingQuotedPrintable && view.text == "café A" {
			found = true
		}
	}
	if !found {
		t.Fatal("UTF-8 prose lost its quoted-printable view")
	}
}
