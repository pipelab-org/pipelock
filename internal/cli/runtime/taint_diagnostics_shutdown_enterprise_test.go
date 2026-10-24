// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package runtime

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMCPTaintDiagnostics_ConductorReturnFencesPlainBuffer(t *testing.T) {
	var output bytes.Buffer
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{}`) }))
	defer upstream.Close()
	s, signer := newConductorApplyTestServerWithConfig(t, "", func(o *ServerOpts) {
		o.Stderr = &output
		o.Stdout = io.Discard
		o.Listen = serverTestEphemeralListen
		o.ListenChanged = true
		o.MCPListen = serverTestEphemeralListen
		o.MCPUpstream = upstream.URL
		o.allowEphemeralListenersForTesting = true
	})
	bundle := signedRuntimePolicyBundle(t, signer, "diagnostic-policy", 1, "", "mode: balanced\n")
	if _, err := s.ApplyConductorPolicyBundle(bundle, ConductorApplyOptions{Resolver: signer.resolver()}); err != nil {
		t.Fatal(err)
	}
	// Exercise the real signed apply and owner shutdown without network pollers.
	s.conductorAudit, s.conductorRemoteKill, s.conductorBundle, s.conductorRollback, s.conductorStale = nil, nil, nil, nil, nil
	assertTaintShutdownPlainBuffer(t, s, &output)
}
