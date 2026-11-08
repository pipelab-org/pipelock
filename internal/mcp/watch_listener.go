// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
)

type watchListenerState struct {
	states                                          *mcpListenerClientStates
	state                                           *mcpListenerClientState
	bound, requireToken, setup, principal, admitted bool
	initializeID                                    json.RawMessage
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
	s.initializeID = append(json.RawMessage(nil), frame.ID...)
	opts.watchSessionKey = state.key
	opts.ToolCfg = s.states.toolConfigAtDriftEpoch(state, opts.toolCfg(), s.states.upstreamDriftEpoch())
	opts.ToolCfgFn = nil
}

func (s *watchListenerState) complete(w http.ResponseWriter, status int, response []byte, opts MCPProxyOpts) {
	if s == nil || !s.setup || status < http.StatusOK || status >= http.StatusMultipleChoices {
		return
	}
	frame := ParseMCPFrame(response)
	var fields map[string]json.RawMessage
	if frame.ParseErr != nil || frame.IsBatch || frame.KeyValidationErr != nil ||
		!bytes.Equal(bytes.TrimSpace(frame.ID), bytes.TrimSpace(s.initializeID)) ||
		json.Unmarshal(response, &fields) != nil || fields["error"] != nil || fields["method"] != nil ||
		!bytes.Equal(fields["jsonrpc"], []byte(`"2.0"`)) || len(bytes.TrimSpace(fields["result"])) == 0 || bytes.TrimSpace(fields["result"])[0] != '{' {
		return
	}
	s.setup = false
	if s.states.admitSetup(s.state) {
		w.Header().Set(listenerSessionTokenHeader, s.state.token)
		s.bound = true
		s.admitted = true
		return
	}
	opts.recordWatch("session_binding", "listener session capacity unavailable", "uninspected", 0, false)
}

func (s *watchListenerState) active() bool {
	return s == nil || s.state == nil || !s.state.revoked.Load()
}
