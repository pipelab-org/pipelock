// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package serviceenv

import (
	"context"
	"errors"
)

func defaultBackend() backend {
	return backend{command: func(context.Context, string, ...string) ([]byte, int, error) {
		return nil, -1, errors.New("service configuration validation requires Linux systemd")
	}}
}
