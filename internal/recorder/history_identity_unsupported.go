// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows && !(js && wasm)

package recorder

import (
	"errors"
	"os"
)

func historyFileIdentity(_ EvidenceLocation, _ string, _ os.FileInfo) (string, error) {
	return "", errors.New("evidence shard identity is unsupported on this platform")
}

func historyHandleIdentity(_ *os.File, _ os.FileInfo) (string, error) {
	return "", errors.New("evidence shard identity is unsupported on this platform")
}

func historyStableFileIdentity(location EvidenceLocation, name string, info os.FileInfo) (string, error) {
	return historyFileIdentity(location, name, info)
}

// EvidenceMetadataIdentity refuses platforms without reliable file identity.
func EvidenceMetadataIdentity(_ string, _ os.FileInfo) (string, error) {
	return "", errors.New("evidence shard identity is unsupported on this platform")
}
