// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"

	"github.com/luckyPipewrench/pipelock/internal/killswitch"
)

// killSwitchEgressTransport repeats the kill-switch check at every outbound
// request made through the shared fetch and forward client. The handlers check
// the switch when a request arrives, but a fetch can spend seconds scanning,
// resolving and following redirects after that. Without this check, a switch
// thrown in that window still lets the next hop leave.
//
// It wraps the RoundTripper rather than the dialer: a redirect to the same host
// reuses a kept-alive connection and never dials, so a dial-time check would
// miss exactly the hop this exists to stop.
type killSwitchEgressTransport struct {
	next http.RoundTripper
	ks   *killswitch.Controller
}

func (t killSwitchEgressTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ks != nil {
		// The request path names the destination, not a pipelock endpoint,
		// so only the client-IP emergency exemption applies here, the same
		// rule intercepted CONNECT tunnels use. A missing client IP matches no
		// exemption and fails closed.
		clientIP, _ := req.Context().Value(ctxKeyClientIP).(string)
		if d := t.ks.IsActiveForIP(clientIP); d.Active {
			// RoundTripper must close the request body, including on error.
			if req.Body != nil {
				_ = req.Body.Close()
			}
			return nil, newBlockedRequestError("kill_switch", killSwitchActiveReason,
				"kill switch active at egress (source "+d.Source+"): "+d.Message)
		}
	}
	return t.next.RoundTrip(req)
}
