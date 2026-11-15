// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestScriptURLReferences(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		limit      int
		want       []string
	}{
		{"module forms", `import"./a.js";import{x}from'../b.js';export{x}from"./c.js";import('./d.js')`, 8, []string{"./a.js", "../b.js", "./c.js", "./d.js"}},
		{"URL literals", `const a="/assets/a.css",b='https://cdn.example/a.js',c="not a URL"`, 8, []string{"/assets/a.css", "https://cdn.example/a.js"}},
		{"relative URL literals", `const paths=['./a.js','../b.css']`, 8, []string{"./a.js", "../b.css"}},
		{"bare module specifier needs import map", `import'package-name'`, 8, nil},
		{"comment bytes are issuer-known", "// '/known.js'\nimport /* '/also-known.js' */ './a.js'", 8, []string{"./a.js", "/known.js", "/also-known.js"}},
		{"computed tail not observed", `fetch('/api/'+sessionValue)`, 8, []string{"/api/"}},
		{"unsupported spellings", "import '/a\\x2fb.js';import(`/computed/${value}`);import'./b.js'", 8, []string{"./b.js"}},
		{"invalid URL", `import'/%zz'`, 8, nil},
		{"unterminated string", `import'/a.js`, 8, nil},
		{"incomplete tail retains known bytes", `import'/a.js';/*`, 8, []string{"/a.js"}},
		{"oversize literal", `import'/` + strings.Repeat("x", issuerCookieMaxPairBytes) + `'`, 8, nil},
		{"oversize source", strings.Repeat(" ", issuerQueryMaxHTMLBytes+1), 8, nil},
		{"bounded", `import'./a.js';import'./b.js'`, 1, []string{"./a.js"}},
		{"relative URLs retain budget", `const incidental='/old';import'./needed.js'`, 1, []string{"./needed.js"}},
		{"duplicate references", `import'./a.js';import'./a.js'`, 8, []string{"./a.js"}},
		{"disabled limit", `import'./a.js'`, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := scriptURLReferences([]byte(tc.body), tc.limit); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("references=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestScriptURLReferencesHostileComment(t *testing.T) {
	// A module-prefix regexp previously rescanned the unterminated comment to
	// EOF for each subsequent from literal. Exercise the existing body cap.
	const unit = "import/* from'./a.js' "
	body := []byte(strings.Repeat(unit, issuerQueryMaxHTMLBytes/len(unit)))
	started := time.Now()
	if got := scriptURLReferences(body, issuerCookieMaxSetCookies); !reflect.DeepEqual(got, []string{"./a.js"}) {
		t.Fatalf("references=%q, want one exact relative URL", got)
	}
	// The prior implementation exceeds this by an order of magnitude; the
	// byte reader takes milliseconds. Keep this check in ordinary CI runs too.
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("hostile script exhausted the observation deadline: %v", elapsed)
	}
}

func TestInterceptIssuedScriptAndCSSReferences(t *testing.T) {
	for _, tc := range []struct {
		name, mediaType string
		body            func(string) string
	}{
		{"module", "text/javascript", func(ref string) string { return `import"` + ref + `";` }},
		{"stylesheet", "text/css", func(ref string) string { return `@import "` + ref + `";` }},
		{"font", "text/css", func(ref string) string { return `@font-face{src:url("` + ref + `")}` }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/assets/" + issuedTestToken() + ".js"
			foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}))
			defer foreign.Close()
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/assets/main" {
					w.Header().Set("Content-Type", tc.mediaType)
					_, _ = io.WriteString(w, tc.body("./"+strings.TrimPrefix(path, "/assets/"))+tc.body(foreign.URL+path))
					return
				}
				_, _ = io.WriteString(w, "ok")
			}))
			defer upstream.Close()
			h := newWebPlatformHarness(t)
			foreignStatus := http.StatusForbidden
			if tc.mediaType == "text/css" {
				// A root stylesheet is a typed producer under the declared
				// resource rule. Script literals remain same-origin only.
				foreignStatus = http.StatusOK
			}
			for _, step := range []struct {
				name, path, agent string
				server            *httptest.Server
				want              int
			}{
				{"before issuance", path, "agent-one", upstream, http.StatusForbidden},
				{"source delivered", "/assets/main", "agent-one", upstream, http.StatusOK},
				{"relative resource", path, "agent-one", upstream, http.StatusOK},
				{"repeat resource", path, "agent-one", upstream, http.StatusOK},
				{"different caller", path, "agent-two", upstream, http.StatusForbidden},
				{"altered path", path + "Q", "agent-one", upstream, http.StatusForbidden},
				{"declared foreign origin", path, "agent-one", foreign, foreignStatus},
				{"undeclared foreign path", path + "Q", "agent-one", foreign, http.StatusForbidden},
				{"DLP still enforced", path + "?leak=" + issuerUnissuedSecret(), "agent-one", upstream, http.StatusForbidden},
				{"unissued query", path + "?other=" + issuedTestToken(), "agent-one", upstream, http.StatusForbidden},
			} {
				t.Run(step.name, func(t *testing.T) {
					if got := h.do(step.server, step.path, step.agent, nil); got != step.want {
						t.Fatalf("status=%d, want %d", got, step.want)
					}
				})
			}
		})
	}
}
