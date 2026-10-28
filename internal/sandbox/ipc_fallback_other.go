// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux || !amd64

package sandbox

func restrictSandboxTarget(_ LayerStatus) error {
	return nil
}

func restrictTargetUnixSockets() error {
	// Normal launches on architectures without a seccomp implementation
	// retain their existing partial-isolation contract. Strict admission is
	// checked separately before any target starts.
	return nil
}
