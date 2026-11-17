// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestBase64ScratchPreservesPaddingVariants(t *testing.T) {
	carriers := []string{
		strings.Repeat("!ordinary text ", 8192),
		strings.Repeat("\r\n", 8192),
		strings.Repeat("A", 8192),
		strings.Repeat("A", 8193) + "=\r\n!",
		strings.Repeat("A", 8194) + "==\xff",
		strings.Repeat("A-_/+", 2048),
		"!" + strings.Repeat("A", maxReassembledTokenLen),
	}
	// Include invalid bytes, padding and either alphabet around quantum edges.
	const symbols = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/-_\r\n="
	const invalid = "! \x00\xff=\r\n"
	for _, length := range []int{0, 1, 3, 4, 255, 256, 257, 4095, 4096, 4097, 8192} {
		for _, at := range []int{0, 1, 3, 4, length / 2, max(0, length-1)} {
			data := make([]byte, length)
			for i := range data {
				data[i] = symbols[(i+length+at)%len(symbols)]
			}
			if at < len(data) {
				data[at] = invalid[at%len(invalid)]
			}
			carriers = append(carriers, string(data))
		}
	}
	for i, text := range carriers {
		short := make([]byte, base64DecodeScratchLen(text))
		full := make([]byte, base64.RawStdEncoding.DecodedLen(len(text)))
		for _, minimum := range []int{0, minKnownSecretSubstringLen} {
			inputs := []string{text, canonicalMixedBase64(text)}
			for _, kind := range []encodedTokenKind{encodedTokenBase64Std, encodedTokenBase64URL} {
				inputs = append(inputs, normalizeEncodedToken(text, kind))
				inputs = append(inputs, normalizeEncodedToken(canonicalMixedBase64(text), kind))
			}
			for _, input := range inputs {
				for _, alphabet := range [][2]*base64.Encoding{{base64.StdEncoding, base64.RawStdEncoding}, {base64.URLEncoding, base64.RawURLEncoding}} {
					want := decodeBase64PaddingVariants(input, alphabet[0], alphabet[1], full, minimum)
					got := decodeBase64PaddingVariants(input, alphabet[0], alphabet[1], short, minimum)
					if got != want {
						t.Fatalf("carrier %d minimum %d: scratch changed decoded bytes", i, minimum)
					}
				}
			}
		}
	}
}

func TestBase64ScratchExcludesRejectedSuffix(t *testing.T) {
	text := "!" + strings.Repeat("ordinary prose ", 1<<16)
	if got := base64DecodeScratchLen(text); got > base64.RawStdEncoding.DecodedLen(maxReassembledTokenLen) {
		t.Fatalf("rejected suffix still sizes scratch: %d bytes", got)
	}
	carrier := base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("valid carrier ", 4096)))
	if got, want := base64DecodeScratchLen(carrier), base64.RawStdEncoding.DecodedLen(len(carrier)); got != want {
		t.Fatalf("valid carrier scratch = %d, want %d", got, want)
	}
}
