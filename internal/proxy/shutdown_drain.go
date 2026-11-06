// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import "time"

// defaultShutdownGrace bounds graceful receipt-producing work.
const defaultShutdownGrace = 5 * time.Second

func (p *Proxy) shutdownGraceOrDefault() time.Duration {
	if p.shutdownGrace > 0 {
		return p.shutdownGrace
	}
	return defaultShutdownGrace
}
