// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package contain

import "context"

func probeDoctorRuntimeSockets(_ context.Context, env *doctorEnv) doctorResult {
	return skip("managed runtime socket isolation requires Linux systemd", "run `"+doctorCommandForPort(env.port)+"` on the Linux containment host")
}
