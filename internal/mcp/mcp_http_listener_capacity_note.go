// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"errors"
	"fmt"
	"io"
)

var errMCPListenerRegistryCapacity = errors.New("MCP listener client-registry capacity exhausted (4096 clients); wait for listener idle expiry (24h) or session end")

const listenerCapacityNote = "pipelock: unauthenticated legacy MCP listener session IDs and Pipelock-issued tokens can each hold a session slot; retained sessions can exhaust listener capacity. In pipelock run, session_profiling.max_sessions is shared with other transports; standalone pipelock mcp proxy --listen uses its own store. Retained listener clients are released on listener idle expiry (24h) or session end, not session_ttl_minutes. Configure authenticated principal state (bearer or principal auth) to bind one principal to one slot. listener_require_state_token does not limit capacity: one anonymous client can obtain many tokens. This note is startup-only; reload does not emit it."

// logListenerCapacityNote reports capacity exposure only when startup options
// allow unauthenticated persistent partitions. It changes no admission policy.
func logListenerCapacityNote(logW io.Writer, opts MCPProxyOpts) {
	if opts.Store == nil || (!listenerHasStatefulControls(opts) && !listenerRequiresStateToken(opts)) ||
		opts.ListenerBearerToken != "" || opts.ListenerBearerTokenFn != nil || opts.ListenerPrincipalResolver != nil {
		return
	}
	_, _ = fmt.Fprintln(logW, listenerCapacityNote)
}
