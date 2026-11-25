// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// The key lasts for one process, like task permissions and CEE fragment state.
// crypto/rand.Read terminates the process if secure randomness is unavailable.
var fingerprintKey = func() [sha256.Size]byte {
	var key [sha256.Size]byte
	_, _ = rand.Read(key[:])
	return key
}()

// fingerprint keeps a stable identifier within one purpose without exposing an
// unkeyed digest of data that may contain credentials. Domains are fixed labels.
func fingerprint(domain string, data []byte) []byte {
	mac := hmac.New(sha256.New, fingerprintKey[:])
	_, _ = mac.Write([]byte(domain + "\x00"))
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}
