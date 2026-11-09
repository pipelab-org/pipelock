// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Microsoft Graph site IDs combine a hostname and two GUIDs, separated by
// commas: https://learn.microsoft.com/en-us/graph/api/resources/site#id-property.
const compositeSiteID = "contosopayroll.vendor.example,2c712604-1370-44e7-a1f5-426573aa38e3,abc94d56-14df-4b04-bc6b-3a4bed9357da"

func TestInterceptServerIssuedCompositeID(t *testing.T) {
	h := newWebPlatformHarness(t)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/sites" {
			_, _ = io.WriteString(w, `{"value":[{"id":"`+compositeSiteID+`"}]}`)
			return
		}
		_, _ = io.WriteString(w, `{"value":[]}`)
	}))
	t.Cleanup(upstream.Close)
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(other.Close)
	const agent = "site-reader"
	path := "/v1.0/sites/" + compositeSiteID + "/drives?$select=id,name,driveType&$top=100"
	if got := h.send(upstream, http.MethodGet, path, agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("before discovery = %d, want 403", got)
	}
	if got := h.send(upstream, http.MethodGet, "/sites", agent, "", ""); got != http.StatusOK {
		t.Fatalf("discovery = %d, want 200", got)
	}
	for _, spelling := range []string{path, strings.ReplaceAll(path, ",", "%2C")} {
		if got := h.send(upstream, http.MethodGet, spelling, agent, "", ""); got != http.StatusOK {
			t.Errorf("issued composite = %d, want 200", got)
		}
	}
	for _, tc := range []struct {
		name, path, agent string
		origin            *httptest.Server
	}{
		{"foreign origin", path, agent, other},
		{"foreign session", path, "other-reader", upstream},
		{"unissued sibling", strings.Replace(path, "2c712604", "3d823715", 1), agent, upstream},
		{"additional segment", "/sites/" + compositeSiteID + "/" + agentBlob, agent, upstream},
		{"additional query", path + "&q=" + agentBlob, agent, upstream},
		{"credential", "/sites/" + compositeSiteID + "/" + issuerUnissuedSecret(), agent, upstream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.send(tc.origin, http.MethodGet, tc.path, tc.agent, "", ""); got != http.StatusForbidden {
				t.Fatalf("request = %d, want 403", got)
			}
		})
	}
}

func TestCompositeIDSendHistory(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/sites")
	for _, value := range []string{compositeSiteID, serverIDListed, "first," + serverIDListed, serverIDListed + ",last"} {
		for _, text := range []string{value, "prefix," + value, value + ",suffix", "prefix," + value + ",suffix", "payload=" + value, "prefix,payload=" + value + ",suffix"} {
			t.Run(text, func(t *testing.T) {
				for _, encoded := range []string{text, url.QueryEscape(text), `{"value":"` + strings.ReplaceAll(text, ",", `\u002c`) + `"}`} {
					s := newTestServerIDStore(t)
					s.recordSent("reader", origin, nil, []byte(encoded), true, time.Now())
					s.mintServerID("reader", origin, value, time.Now())
					if s.serverIDIssued("reader", origin, value) {
						t.Fatal("reflected comma-delimited value minted")
					}
				}
			})
		}
	}
}

func TestCompositeIDShapeAndLimits(t *testing.T) {
	if !issuerServerIDShaped(compositeSiteID) {
		t.Fatal("composite site ID rejected")
	}
	for _, value := range []string{compositeSiteID + "/path", compositeSiteID + " ", strings.ReplaceAll(compositeSiteID, ",", "%2C"), strings.Repeat("a,", issuerServerIDMaxLen)} {
		if issuerServerIDShaped(value) {
			t.Fatal("invalid segment shape admitted")
		}
	}
	s := newTestServerIDStore(t)
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/sites")
	s.recordSent("reader", origin, nil, []byte(strings.Repeat("opaque-object-id,", issuerSentMaxTokensPerRequest+1)), true, time.Now())
	s.mintServerID("reader", origin, compositeSiteID, time.Now())
	if s.serverIDIssued("reader", origin, compositeSiteID) || s.sentUnreadable["reader"] == issuerHistoryComplete {
		t.Fatal("token expansion limit did not fail closed")
	}
}

// An ordinary comma-separated list must not exhaust the per-request token cap,
// and a composite ID sent inside it must still read as reflected.
func TestCompositeIDListKeepsHistoryReadable(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/sites")
	var list []string
	for i := 0; i < 400; i++ {
		list = append(list, strings.Replace("2c712604-1370-44e7-a1f5-0000000000", "0000000000", strings.Repeat(string(rune('a'+i%26)), 10), 1)+"-"+strings.Repeat(string(rune('a'+i/26)), 3))
	}
	s := newTestServerIDStore(t)
	s.recordSent("reader", origin, nil, []byte("ids="+strings.Join(list, ",")), true, time.Now())
	if s.sentUnreadable["reader"] != issuerHistoryComplete {
		t.Fatal("a 400-item list tainted the session")
	}
	s.mintServerID("reader", origin, list[10]+","+list[11]+","+list[12], time.Now())
	if s.serverIDIssued("reader", origin, list[10]+","+list[11]+","+list[12]) {
		t.Fatal("composite reflected inside a sent list minted")
	}
	s.mintServerID("reader", origin, compositeSiteID, time.Now())
	if !s.serverIDIssued("reader", origin, compositeSiteID) {
		t.Fatal("unsent composite not minted after a long list")
	}
	// Recombining already-sent fields introduces no eligible new word. The
	// conservative proof withholds relief even for a previously unseen order.
	s.mintServerID("reader", origin, list[0]+","+list[2], time.Now())
	if s.serverIDIssued("reader", origin, list[0]+","+list[2]) {
		t.Fatal("known fields minted without an introduced word")
	}
}
