// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"encoding/json"
	"io"
	"net/http"
)

// ReloadOutcome describes a completed daemon transaction, not offline validity.
// Source hashes identify input bytes; the canonical hash identifies only the
// policy-semantic view. Neither asserts that every candidate setting is live.
type ReloadOutcome struct {
	InstanceID            string   `json:"instance_id"`
	Generation            uint64   `json:"activation_generation"`
	Trigger               string   `json:"trigger"`
	CandidateSourceHash   string   `json:"candidate_source_hash,omitempty"`
	AcceptedSourceHash    string   `json:"last_accepted_source_hash,omitempty"`
	CanonicalPolicyHash   string   `json:"canonical_policy_hash"`
	Verdict               string   `json:"verdict"`
	Reason                string   `json:"reason,omitempty"`
	PendingRestart        bool     `json:"pending_restart"`
	RestartRequiredFields []string `json:"restart_required_fields"`
	ReloadAvailable       bool     `json:"reload_available"`
	WatcherState          string   `json:"watcher_state"`
}

// Reload verdicts are shared by the daemon and its operator client.
const (
	ReloadAccepted        = "accepted"
	ReloadUnchanged       = "unchanged"
	ReloadRejected        = "rejected"
	ReloadRestartRequired = "restart_required"
	ReloadUncertain       = "uncertain"
	ReloadUnavailable     = "unavailable"
	ReloadCompensated     = "compensated"
)

// SetConfigControl binds daemon-owned operations before serving any listeners.
// A proxy without a runtime controller keeps these endpoints unavailable.
func (h *SessionAPIHandler) SetConfigControl(status, reload func() ReloadOutcome) {
	h.configStatus = status
	h.configReload = reload
}

// HandleConfigStatus returns the same snapshot used by reload completion.
func (h *SessionAPIHandler) HandleConfigStatus(w http.ResponseWriter, r *http.Request) {
	h.handleConfigControl(w, r, http.MethodGet, h.configStatus)
}

// HandleConfigReload reloads only the daemon's configured source. Callers may
// not supply paths, bytes, or query options.
func (h *SessionAPIHandler) HandleConfigReload(w http.ResponseWriter, r *http.Request) {
	h.handleConfigControl(w, r, http.MethodPost, h.configReload)
}

func (h *SessionAPIHandler) handleConfigControl(w http.ResponseWriter, r *http.Request, method string, operation func() ReloadOutcome) {
	if r.Method != method {
		w.Header().Set("Allow", method)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !h.authenticate(w, r) {
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "config control accepts no query parameters", http.StatusBadRequest)
		return
	}
	if r.Body != nil {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1))
		if err != nil || len(body) != 0 {
			http.Error(w, "config control accepts no request body", http.StatusBadRequest)
			return
		}
	}
	if operation == nil {
		http.Error(w, "daemon config control unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(operation())
}
