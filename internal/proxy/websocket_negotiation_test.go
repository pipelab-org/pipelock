// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import "testing"

func TestWebSocketLegacySubprotocolPreserved(t *testing.T) {
	testWebSocketSubprotocolPreserved(t, false)
}
