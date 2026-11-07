// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import "net/http"

type watchListenerState struct {
	states                     *mcpListenerClientStates
	state                      *mcpListenerClientState
	bound, requireToken, setup bool
}

func (s *watchListenerState) prepare(frame MCPFrame, opts *MCPProxyOpts) {
	if s == nil || s.bound || !s.requireToken || frame.Method != "initialize" || frame.IsBatch || frame.ProtocolVersionPresent {
		return
	}
	state, err := s.states.newSetupState()
	if err != nil {
		opts.recordWatch("session_binding", "listener session setup unavailable", "uninspected", 0, false)
		return
	}
	s.state = state
	s.setup = true
	opts.watchSessionKey = state.key
	opts.ToolCfg = s.states.toolConfigAtDriftEpoch(state, opts.toolCfg(), s.states.upstreamDriftEpoch())
	opts.ToolCfgFn = nil
}

func (s *watchListenerState) complete(w http.ResponseWriter, status int, opts MCPProxyOpts) {
	if s == nil || !s.setup || status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	s.setup = false
	if s.states.admitSetup(s.state) {
		w.Header().Set(listenerSessionTokenHeader, s.state.token)
		s.bound = true
		return
	}
	opts.recordWatch("session_binding", "listener session capacity unavailable", "uninspected", 0, false)
}

func (s *watchListenerState) active() bool {
	return s == nil || s.state == nil || !s.state.revoked.Load()
}
