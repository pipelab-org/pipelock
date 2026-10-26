// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"io"
)

// logListenerCapacityNote reports the shared-store consequence of legacy
// client-selected partitions. It changes no admission or retention policy.
func logListenerCapacityNote(logW io.Writer, opts MCPProxyOpts) {
	if opts.Store == nil || listenerRequiresStateToken(opts) ||
		opts.ListenerBearerToken != "" || opts.ListenerBearerTokenFn != nil || opts.ListenerPrincipalResolver != nil {
		return
	}
	_, _ = fmt.Fprintln(logW, "pipelock: legacy MCP listener session IDs share session_profiling.max_sessions with other transports; retained sessions can exhaust shared capacity. For multi-client listeners, configure authenticated principal state. For legacy compatibility, consider mcp_session_binding.listener_require_state_token; issued tokens are not a per-caller quota.")
}
