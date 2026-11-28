// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"

	"filippo.io/edwards25519"

	"github.com/luckyPipewrench/pipelock/internal/evidencename"
)

type signature struct {
	key string
	raw []byte
}

// Record retains the exact signed bytes and the decoded common members.
type Record struct {
	Common
	Payload []byte
	ID      string

	values map[string]any
	sig    signature
	sigs   []signature
}

// Digest returns a receipt digest string over data.
func Digest(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// PAE returns the DSSE v1 pre-authentication encoding of a receipt payload.
func PAE(payload []byte) []byte {
	prefix := "DSSEv1 " + strconv.Itoa(len(PayloadType)) + " " + PayloadType + " " + strconv.Itoa(len(payload)) + " "
	return append([]byte(prefix), payload...)
}

// Genesis returns the previous-record value required at stream position zero.
func Genesis(stream string) string {
	return Digest([]byte(layoutGenesisDomain + "\x00" + stream))
}

const profilePrefix = evidencename.ReceiptProfilePrefix

func parseLine(line []byte, skip string) (Record, string) {
	if skip != codeLineSize && len(line) > maxLineBytes {
		return Record{}, codeLineSize
	}
	content, ok := bytes.CutPrefix(line, []byte(layoutPrefix))
	if !ok {
		if profile, found := bytes.CutPrefix(line, []byte(profilePrefix)); found {
			if value, _, delimited := bytes.Cut(profile, []byte("\"")); delimited && string(value) != "v3+json" {
				return Record{}, codeUnknownProfile
			}
		}
		return Record{}, codeLineLayout
	}

	var sigs []signature
	last := ""
	keyWidth := len("sha256:") + sha256.Size*2
	sigWidth := base64.StdEncoding.EncodedLen(layoutSignatureBytes)
	for {
		key, rest, valid := fixedMember(content, layoutEntryPrefix, keyWidth)
		if !valid || !isDigest(string(key)) || skip != codeLineLayout && string(key) <= last {
			return Record{}, codeLineLayout
		}
		encoded, rest, valid := fixedMember(rest, layoutSignaturePrefix, sigWidth)
		if !valid {
			return Record{}, codeLineLayout
		}
		raw, valid := decodeBase64(string(encoded), layoutSignatureBytes)
		if !valid {
			return Record{}, codeLineLayout
		}
		content, valid = bytes.CutPrefix(rest, []byte(layoutEntrySuffix))
		if !valid {
			return Record{}, codeLineLayout
		}
		last = string(key)
		sigs = append(sigs, signature{last, raw})
		tail, more := bytes.CutPrefix(content, []byte(layoutEntrySeparator))
		if !more {
			break
		}
		if len(sigs) == maxSignatures {
			return Record{}, codeLineLayout
		}
		content = tail
	}

	payload, ok := bytes.CutPrefix(content, []byte(layoutPayloadPrefix))
	if !ok {
		return Record{}, codeLineLayout
	}
	payload, ok = bytes.CutSuffix(payload, []byte(layoutSuffix))
	if !ok || len(payload) == 0 || payload[0] != '{' {
		return Record{}, codeLineLayout
	}
	cursor := payloadParser{data: payload, allowUnordered: skip == codePayloadLayout}
	values, parsed := cursor.object(1)
	if !parsed {
		return Record{}, codePayloadLayout
	}
	if cursor.pos != len(payload) {
		return Record{}, codeLineLayout
	}

	if _, valid := matchObject(values, "Common"); skip != codeCommonSchema && (!valid || !sortedStrings(values["crit"], true)) {
		return Record{}, codeCommonSchema
	}
	var common Common
	if err := json.Unmarshal(payload, &common); err != nil {
		return Record{}, codeCommonSchema
	}
	body, _ := values["body"].(map[string]any)
	record := Record{
		Common: common, Payload: bytes.Clone(payload),
		ID: Digest(PAE(payload)), values: body, sigs: sigs,
	}
	for _, entry := range sigs {
		if entry.key == record.Signer {
			record.sig = entry
			return record, ""
		}
	}
	if skip == codeSignerMissing {
		record.sig = sigs[0]
		return record, ""
	}
	return Record{}, codeSignerMissing
}

func fixedMember(input []byte, prefix string, width int) (member, rest []byte, ok bool) {
	rest, ok = bytes.CutPrefix(input, []byte(prefix))
	if !ok || len(rest) < width {
		return nil, nil, false
	}
	return rest[:width], rest[width:], true
}

func decodeBase64(text string, size int) ([]byte, bool) {
	raw, err := base64.StdEncoding.Strict().DecodeString(text)
	return raw, err == nil && len(raw) == size && base64.StdEncoding.EncodeToString(raw) == text
}

func isLowerHex(text string, width int) bool {
	if len(text) != width {
		return false
	}
	for i := range len(text) {
		if !lowerHex(text[i]) {
			return false
		}
	}
	return true
}

func lowerHex(ch byte) bool {
	return ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f'
}

func isDigest(text string) bool {
	tail, ok := strings.CutPrefix(text, "sha256:")
	return ok && isLowerHex(tail, sha256.Size*2)
}

// The order, in little-endian bytes. Scalar APIs on this curve reduce by this
// value, so the subgroup check must instead use unreduced point operations.
var groupOrder = [32]byte{
	0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
	0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
	0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0x10,
}

func canonicalPoint(encoded []byte) (*edwards25519.Point, bool) {
	point, err := new(edwards25519.Point).SetBytes(encoded)
	return point, err == nil && bytes.Equal(encoded, point.Bytes()) &&
		point.Equal(edwards25519.NewIdentityPoint()) == 0
}

func primeOrder(point *edwards25519.Point) bool {
	multiple := edwards25519.NewIdentityPoint()
	for i := len(groupOrder) - 1; i >= 0; i-- {
		for bit := 7; bit >= 0; bit-- {
			multiple.Add(multiple, multiple)
			if groupOrder[i]>>bit&1 != 0 {
				multiple.Add(multiple, point)
			}
		}
	}
	return multiple.Equal(edwards25519.NewIdentityPoint()) == 1
}

type validatedKey struct {
	public ed25519.PublicKey
	valid  bool
}

func checkSignature(record Record, key validatedKey, skip string) string {
	if skip != codeSignatureKey && Digest(key.public) != record.Signer {
		return codeSignatureKey
	}
	return verifyEd25519(PAE(record.Payload), key, record.sig.raw, skip)
}

func verifyEd25519(message []byte, key validatedKey, signature []byte, skip string) string {
	if skip != codeSignatureKey && !key.valid {
		return codeSignatureKey
	}
	if _, err := new(edwards25519.Scalar).SetCanonicalBytes(signature[32:]); err != nil && skip != codeSignatureScalar {
		return codeSignatureScalar
	}
	if _, valid := canonicalPoint(signature[:32]); !valid && skip != codeSignaturePoint {
		return codeSignaturePoint
	}
	// Go's pure Ed25519 verifier compares the encoded result of the
	// cofactorless equation with R.
	if skip != codeSignatureEquation && !ed25519.Verify(key.public, message, signature) {
		return codeSignatureEquation
	}
	return ""
}

func validateKey(raw []byte) validatedKey {
	point, valid := canonicalPoint(raw)
	return validatedKey{public: raw, valid: valid && primeOrder(point)}
}

// ExportDSSE converts a storage line to a DSSE envelope. It validates the
// storage structure and retains the signatures without checking their trust.
func ExportDSSE(line []byte) ([]byte, string) {
	record, code := parseLine(line, "")
	if code != "" {
		return nil, code
	}

	// The envelope values are base64, fixed text, or validated key IDs.
	// None require JSON escaping.
	data := base64.StdEncoding.AppendEncode([]byte("{\"payload\":\""), record.Payload)
	data = append(data, "\",\"payloadType\":\""+PayloadType+"\",\"signatures\":["...)
	for i, entry := range record.sigs {
		if i != 0 {
			data = append(data, layoutEntrySeparator...)
		}
		data = append(data, layoutEntryPrefix...)
		data = append(data, entry.key...)
		data = append(data, layoutSignaturePrefix...)
		data = base64.StdEncoding.AppendEncode(data, entry.raw)
		data = append(data, layoutEntrySuffix...)
	}
	return append(data, ']', '}'), ""
}
