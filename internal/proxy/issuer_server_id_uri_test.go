// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Neutral fixtures cover Graph's composite site ID, b!-prefixed drive ID and
// opaque root item ID through the same generic issuer-evidence mechanism.
func TestInterceptIssuedLibraryWorkflow(t *testing.T) {
	h := newWebPlatformHarness(t)
	const driveID = "b!" + serverIDListed + "_" + serverIDOther
	const agent = "library-reader"
	root := "/v1.0/drives/" + driveID + "/root"
	items := "/v1.0/drives/" + driveID + "/items/" + serverIDKeyOnly
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/discovery":
			_, _ = io.WriteString(w, `{"value":[{"id":"`+compositeSiteID+`"}]}`)
		case "/v1.0/sites/" + compositeSiteID + "/drives":
			_, _ = io.WriteString(w, `{"value":[{"id":"`+driveID+`","driveType":"documentLibrary"}]}`)
		case root:
			_, _ = io.WriteString(w, `{"id":"`+serverIDKeyOnly+`","folder":{"childCount":0}}`)
		default:
			_, _ = io.WriteString(w, `{"value":[]}`)
		}
	}))
	t.Cleanup(upstream.Close)
	if got := h.send(upstream, http.MethodGet, root, agent, "", ""); got != http.StatusForbidden {
		t.Fatalf("unissued drive root = %d, want 403", got)
	}
	for _, path := range []string{
		"/discovery",
		"/v1.0/sites/" + compositeSiteID + "/drives?$select=id,name,driveType&$top=100",
		root + "?$select=id,name,folder,parentReference,sharepointIds,webUrl",
		items + "/children?$select=id,name,folder,file,parentReference,webUrl&$top=100",
		items + "/permissions?$top=100",
	} {
		if got := h.send(upstream, http.MethodGet, path, agent, "", ""); got != http.StatusOK {
			t.Fatalf("workflow step %s = %d, want 200", path, got)
		}
	}
	for _, path := range []string{root + "?q=" + agentBlob, items + "/" + agentBlob, root + "/" + issuerUnissuedSecret()} {
		if got := h.send(upstream, http.MethodGet, path, agent, "", ""); got != http.StatusForbidden {
			t.Fatalf("additional payload = %d, want 403", got)
		}
	}
}

func TestIssuerLiteralPathCharacters(t *testing.T) {
	origin := mustIssuerQueryURL(t, "https://api.vendor.example/items")
	for _, separator := range issuerIDDelimiters {
		value := serverIDListed + string(separator) + serverIDOther
		t.Run(string(separator), func(t *testing.T) {
			s := newTestServerIDStore(t)
			s.recordSent("reader", origin, nil, nil, true, time.Now())
			s.mintServerID("reader", origin, value, time.Now())
			if !s.serverIDIssued("reader", origin, value) {
				t.Fatal("server-issued literal path ID refused")
			}
			for _, text := range []string{value, "prefix," + value + ",suffix", "key=" + url.QueryEscape(value), `{"id":"` + value + `"}`} {
				sent := newTestServerIDStore(t)
				sent.recordSent("reader", origin, nil, []byte(text), true, time.Now())
				sent.mintServerID("reader", origin, value, time.Now())
				if sent.serverIDIssued("reader", origin, value) {
					t.Fatal("client-supplied value minted as server-issued")
				}
			}
		})
	}
	for _, separator := range []string{"/", "%", "?", "#", " ", "\x00", "\r", "\n"} {
		if issuerServerIDShaped(serverIDListed + separator + serverIDOther) {
			t.Fatalf("nonliteral segment character %q accepted", separator)
		}
	}
	s := newTestServerIDStore(t)
	s.recordSent("reader", origin, nil, nil, true, time.Now())
	maximum := strings.Repeat("x", issuerServerIDMaxLen)
	s.mintServerID("reader", origin, maximum, time.Now())
	if !s.serverIDIssued("reader", origin, maximum+":") || s.serverIDIssued("reader", origin, maximum+"::") {
		t.Fatal("maximum-length relative addressing changed")
	}
}

// Shaped strings that can never mint, such as timestamps, must not spend the
// per-response mint budget the later IDs of a long listing need.
func TestIssuerListingTimestampsKeepIDBudget(t *testing.T) {
	h := newWebPlatformHarness(t)
	const items = 200
	id := func(i int) string {
		return fmt.Sprintf("Qx%dvPq2LmZ9tRw4KbNy8JsHd3FgUcVe6Ta%dMo5", i*7919+13, i*104729+7)
	}
	var b strings.Builder
	b.WriteString(`{"value":[`)
	for i := 0; i < items; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"createdDateTime":"2026-11-02T16:43:00Z","id":%q,"lastModifiedDateTime":"2026-11-02T16:44:00Z","fileSystemInfo":{"createdDateTime":"2026-11-02T16:43:00Z","lastModifiedDateTime":"2026-11-02T16:44:00Z"}}`, id(i))
	}
	b.WriteString(`]}`)
	listing := b.String()
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/list" {
			_, _ = io.WriteString(w, listing)
			return
		}
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(upstream.Close)
	if got := h.send(upstream, http.MethodGet, "/list", "lister", "", ""); got != http.StatusOK {
		t.Fatalf("listing = %d, want 200", got)
	}
	for i := 0; i < items; i++ {
		if got := h.send(upstream, http.MethodGet, "/v1/items/"+id(i), "lister", "", ""); got != http.StatusOK {
			t.Fatalf("item %d = %d, want 200", i, got)
		}
	}
}
