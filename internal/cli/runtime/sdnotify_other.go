// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package runtime

import "io"

func sdNotifySafeStatus(text string) string { return text }

func sdNotify(_ string) (bool, error) { return false, nil }

func sdNotifyOrLog(_ io.Writer, _ string) {}

func sdNotifyReloading(_ io.Writer) {}

func sdNotifyReloadComplete(_ io.Writer, _ error) {}

func sdNotifyConfigComplete(_ io.Writer, _ string) {}
