// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sdnotify

// Send is a no-op on platforms without systemd.
func Send(_ string) (bool, error) { return false, nil }
