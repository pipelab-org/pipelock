// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"errors"
	"io"
	"regexp"
)

// ProfileEnvelopePrefix marks receipt-profile envelopes before decoding.
const ProfileEnvelopePrefix = "{\"payloadType\":\"application/vnd.pipelock.receipt."

var profileFilename = regexp.MustCompile(`\.receipt-v([0-9]+)\.jsonl$`)

// ProfileFilenameVersion returns the version claimed by a receipt-profile
// filename, or an empty string for an unclaimed name.
func ProfileFilenameVersion(name string) string {
	match := profileFilename.FindStringSubmatch(name)
	if match == nil {
		return ""
	}
	return match[1]
}

// HasProfileEnvelope checks the exact receipt-profile prefix without decoding
// the envelope. A short file with no complete prefix does not claim a profile.
func HasProfileEnvelope(r io.Reader) (bool, error) {
	prefix := make([]byte, len(ProfileEnvelopePrefix))
	if _, err := io.ReadFull(r, prefix); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return false, nil
		}
		return false, err
	}
	return bytes.Equal(prefix, []byte(ProfileEnvelopePrefix)), nil
}
