// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package clockhook carries the license clock setter from package edition to
// its test-support package. Go's internal rule limits importers to the
// internal/edition tree, so production packages cannot reach the setter.
package clockhook

// SetLicenseClock installs a *edition.LicenseClock (nil restores the wall
// clock) and returns a restore function. Package edition sets it in init.
var SetLicenseClock func(clock any) (restore func())
