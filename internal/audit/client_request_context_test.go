// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import "testing"

func TestNewClientRequestLogContextOmitsRequestContent(t *testing.T) {
	ctx := NewClientRequestLogContext("ADAPTIVE", "10.0.0.7", "req-1")
	if ctx.Method() != "ADAPTIVE" || ctx.ClientIP() != "10.0.0.7" || ctx.RequestID() != "req-1" {
		t.Fatalf("context = %+v", ctx)
	}
	if ctx.URL() != "" || ctx.target != "" || ctx.resource != "" {
		t.Fatalf("context carries request content: %+v", ctx)
	}
}
