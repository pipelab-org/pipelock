// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/emit"
)

func TestDropURLContentSegmentsRejectsInvalidDestinations(t *testing.T) {
	tests := []struct {
		raw  string
		want string
	}{
		{"data:payloadcanary", "[redacted-url]"},
		{"data:123", "[redacted-url]"},
		{"mailto:123", "[redacted-url]"},
		{"payloadcanary:123", "[redacted-url]"},
		{"payloadcanary://api.vendor.example", "[redacted-url]"},
		{"data://api.vendor.example", "[redacted-url]"},
		{"http:123", "[redacted-url]"},
		{"mailto:payloadcanary", "[redacted-url]"},
		{"javascript:payloadcanary", "[redacted-url]"},
		{"https:///payloadcanary", "[redacted-url]"},
		{"/payloadcanary", "[redacted-url]"},
		{"api.vendor.example:payloadcanary", "[redacted-url]"},
		{"api.vendor.example:65536", "[redacted-url]"},
		{"api.vendor.example:", "[redacted-url]"},
		{"api.vendor.example:0", "[redacted-url]"},
		{"api..vendor.example", "[redacted-url]"},
		{"-api.vendor.example", "[redacted-url]"},
		{"api-.vendor.example", "[redacted-url]"},
		{"api vendor.example", "[redacted-url]"},
		{"api%2fvendor.example", "[redacted-url]"},
		{"[invalid]:443", "[redacted-url]"},
		{"https://[invalid]:443", "[redacted-url]"},
		{"https://[fe80::1%25payloadcanary]", "[redacted-url]"},
		{"api_vendor.example", "[redacted-url]"},
		{"https://api.vendor.example/%zz", "[redacted-url]"},
		{"api.vendor.example:443", "api.vendor.example:443"},
		{"localhost:8080", "localhost:8080"},
		{"service:8080", "[redacted-url]"},
		{"//service:8080", "service:8080"},
		{"http://service:8080", "http://service:8080"},
		{"HTTPS://api.vendor.example", "https://api.vendor.example"},
		{"192.0.2.1:443", "192.0.2.1:443"},
		{"[2001:db8::1]:443", "[2001:db8::1]:443"},
		{"https://[2001:db8::1]:443", "https://[2001:db8::1]:443"},
		{"ws://api.vendor.example", "ws://api.vendor.example"},
		{"wss://api.vendor.example", "wss://api.vendor.example"},
		{"api.vendor.example.", "api.vendor.example."},
		{"https://user:payloadcanary@api.vendor.example", "https://api.vendor.example"},
		{"user:payloadcanary@api.vendor.example", "api.vendor.example"},
		{"//api.vendor.example", "api.vendor.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"bücher.example", "bücher.example"},
		{strings.Repeat("a", 64) + ".example", "[redacted-url]"},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			for _, keepPath := range []bool{false, true} {
				if got := dropURLContentSegments(tt.raw, keepPath); got != tt.want {
					t.Errorf("keepPath=%v: got %q, want %q", keepPath, got, tt.want)
				}
			}
		})
	}
}

func TestHTTPAuditDestinationsRedactedInBothOutputs(t *testing.T) {
	canary := strings.Join([]string{"payload", "canary"}, "")
	raw := "https://user:" + canary + "@api.vendor.example:443/" + canary + "?token=" + canary + "#" + canary
	const destination = "https://api.vendor.example:443"
	tests := []struct {
		name   string
		log    func(*Logger, string)
		fields []string
	}{
		{"allowed", func(l *Logger, value string) {
			l.LogAllowed(LogContext{method: testMethodGet, url: value, target: value}, 200, 10, time.Millisecond)
		}, []string{"url", "target"}},
		{"error", func(l *Logger, value string) {
			l.LogError(LogContext{method: testMethodGet, url: value, target: value}, errors.New("upstream unavailable"))
		}, []string{"url", "target"}},
		{"URL error", func(l *Logger, value string) {
			l.LogError(LogContext{url: value}, &url.Error{Op: "Get", URL: value, Err: errors.New("upstream unavailable")})
		}, []string{"url"}},
		{"wrapped URL error", func(l *Logger, value string) {
			l.LogError(LogContext{url: value}, fmt.Errorf("fetch: %w", &url.Error{Op: "Get", URL: value, Err: errors.New("upstream unavailable")}))
		}, []string{"url"}},
		{"nested URL error", func(l *Logger, value string) {
			// Typed wrappers can retain a second URL in the cause.
			nested := "https://other.vendor.example:payloadcanary/" + value
			l.LogError(LogContext{url: value}, &url.Error{Op: "Get", URL: value, Err: fmt.Errorf("failed to parse Location header %q: %w", nested,
				&url.Error{Op: "parse", URL: nested, Err: errors.New(`invalid port ":payloadcanary" after host`)})})
		}, []string{"url"}},
		{"quoted URL error", func(l *Logger, value string) {
			value += `?token="payloadcanary"\payloadcanary`
			l.LogError(LogContext{url: value}, &url.Error{Op: "Get", URL: value, Err: errors.New("upstream unavailable")})
		}, []string{"url"}},
		{"parse URL error", func(l *Logger, value string) {
			_, err := url.Parse("https://api.vendor.example:payloadcanary/" + value)
			l.LogError(LogContext{url: value}, err)
		}, []string{"url"}},
		{"joined URL errors", func(l *Logger, value string) {
			l.LogError(LogContext{url: value}, errors.Join(
				&url.Error{Op: "Get", URL: value, Err: errors.New("upstream unavailable")},
				&url.Error{Op: "Get", URL: "https://second.vendor.example/payloadcanary?token=payloadcanary", Err: errors.New("also unavailable")}))
		}, []string{"url"}},
		{"URL error raw cause", func(l *Logger, value string) {
			l.LogError(LogContext{url: value}, &url.Error{Op: "Get", URL: value, Err: errors.New("cause payloadcanary")})
		}, []string{"url"}},
		{"URL error raw wrapper", func(l *Logger, value string) {
			l.LogError(LogContext{url: value}, fmt.Errorf("wrapper payloadcanary: %w", &url.Error{Op: "Get", URL: value, Err: auditUnformattableError{}}))
		}, []string{"url"}},
		{"identity collision", func(l *Logger, value string) {
			l.LogAgentIdentityCollision(LogContext{method: testMethodGet, url: value, target: value}, "reserved")
		}, []string{"url", "target"}},
		{"response exemption", func(l *Logger, value string) {
			l.LogResponseScanExempt(LogContext{method: testMethodGet, url: value, target: value}, "api.vendor.example")
		}, []string{"url", "target"}},
		{"full trust exemption", func(l *Logger, value string) {
			l.LogResponseScanExemptFullTrust(LogContext{method: testMethodGet, url: value, target: value}, "api.vendor.example")
		}, []string{"url", "target"}},
		{"over cap exemption", func(l *Logger, value string) {
			l.LogResponseScanExemptOverCapUnscanned(LogContext{method: testMethodGet, url: value, target: value}, "api.vendor.example", "fetch", 20, 10)
		}, []string{"url", "target"}},
		{"media", func(l *Logger, value string) {
			l.LogMediaExposure(LogContext{method: testMethodGet, url: value}, MediaExposureInfo{Transport: "fetch"})
		}, []string{"url"}},
		{"taint", func(l *Logger, value string) {
			l.LogTaintDecision(LogContext{method: testMethodGet, url: value}, TaintDecision{SourceURL: value, Decision: "allow"})
		}, []string{"url", "source_url"}},
		{"header DLP", func(l *Logger, value string) {
			l.LogHeaderDLP(LogContext{method: testMethodGet, url: value, target: value}, "Authorization", "warn", nil, nil)
		}, []string{"url", "target"}},
		{"shield", func(l *Logger, value string) {
			l.LogShieldRewrite("tracking", 1, "fetch", value, testClientIP, testReqID)
		}, []string{"url"}},
		{"authority", func(l *Logger, value string) {
			l.LogAuthorityVerification(LogContext{method: testMethodGet, url: value, target: value}, AuthorityVerification{Decision: "allow"})
		}, []string{"url", "target"}},
		{"tunnel open", func(l *Logger, value string) {
			l.LogTunnelOpen(LogContext{target: value})
		}, []string{"target"}},
		{"tunnel close", func(l *Logger, value string) {
			l.LogTunnelClose(LogContext{target: value}, 10, time.Millisecond)
		}, []string{"target"}},
		{"websocket open", func(l *Logger, value string) {
			l.LogWSOpen(value, testClientIP, testReqID, "")
		}, []string{"target"}},
		{"websocket close", func(l *Logger, value string) {
			l.LogWSClose(WSCloseEvent{Target: value})
		}, []string{"target"}},
		{"websocket blocked", func(l *Logger, value string) {
			l.LogWSBlocked(WSBlockedEvent{Target: value, Scanner: "dlp"})
		}, []string{"target"}},
		{"intercept", func(l *Logger, value string) {
			l.LogInterceptHTTP(LogContext{method: testMethodGet, url: value, target: value}, InterceptTiming{StatusCode: 200})
		}, []string{"url", "target"}},
		{"forward", func(l *Logger, value string) {
			l.LogForwardHTTP(LogContext{method: testMethodGet, url: value, target: value}, 200, 10, time.Millisecond)
		}, []string{"url", "target"}},
		{"redirect", func(l *Logger, value string) {
			l.LogRedirect(value, value, testClientIP, testReqID, "", 1)
		}, []string{"original_url", "redirect_url"}},
		{"blocked destination", func(l *Logger, value string) {
			l.LogBlocked(LogContext{method: testMethodGet, url: value, target: value}, "ssrf", "destination blocked")
		}, []string{"url", "target"}},
	}
	for _, tt := range tests {
		for _, input := range []struct{ raw, want string }{
			{raw, destination},
			{"data:payloadcanary", "[redacted-url]"},
			{"data:123", "[redacted-url]"},
			{"payloadcanary://api.vendor.example", "[redacted-url]"},
			{"api.vendor.example:443/" + canary + "?token=" + canary, "api.vendor.example:443"},
		} {
			t.Run(tt.name+"/"+input.raw, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.log")
				logger, err := New("json", "file", path, true, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sink := &collectingSink{}
				emitter := emit.NewEmitter("test-instance", sink)
				t.Cleanup(func() { _ = emitter.Close() })
				logger.SetEmitter(emitter)
				tt.log(logger, input.raw)
				logger.Close()
				entries := readInterceptEntries(t, path)
				if len(entries) != 1 {
					t.Fatalf("local entries=%d, want 1", len(entries))
				}
				event := sink.onlyEvent(t)
				if entries[0]["event"] != event.Type {
					t.Errorf("local event=%v, emitted event=%s", entries[0]["event"], event.Type)
				}

				for _, fields := range []map[string]any{entries[0], event.Fields} {
					for _, field := range tt.fields {
						if fields[field] != input.want {
							t.Errorf("%s=%q, want %q", field, fields[field], input.want)
						}
					}
					for field, value := range fields {
						if s, ok := value.(string); ok && strings.Contains(s, "payloadcanary") {
							t.Errorf("payload reached %s: %q", field, s)
						}
					}
				}
			})
		}
	}
}

func TestAdaptiveAuditSanitizesBothOutputs(t *testing.T) {
	const dirty = "value\x1b[2J\x00"
	const clean = "value"
	tests := []struct {
		name   string
		log    func(*Logger, string, string)
		fields []string
	}{
		{"anomaly", func(l *Logger, ip, id string) {
			l.LogSessionAnomaly(dirty, dirty, dirty, ip, id, 1)
		}, []string{"session", "anomaly_type", "detail"}},
		{"escalation", func(l *Logger, ip, id string) {
			l.LogAdaptiveEscalation(dirty, dirty, dirty, ip, id, 1)
		}, []string{"session", "from", "to"}},
		{"upgrade", func(l *Logger, ip, id string) {
			l.LogAdaptiveUpgrade(dirty, dirty, dirty, dirty, dirty, ip, id)
		}, []string{"session", "escalation_level", "from_action", "to_action", "scanner"}},
	}
	for _, tt := range tests {
		for _, identifiers := range []string{dirty, ""} {
			t.Run(tt.name+"/"+identifiers, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "audit.log")
				logger, err := New("json", "file", path, true, true)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(logger.Close)
				sink := &collectingSink{}
				emitter := emit.NewEmitter("test-instance", sink)
				t.Cleanup(func() { _ = emitter.Close() })
				logger.SetEmitter(emitter)
				tt.log(logger, identifiers, identifiers)
				logger.Close()
				entries := readInterceptEntries(t, path)
				if len(entries) != 1 {
					t.Fatalf("local entries=%d, want 1", len(entries))
				}
				event := sink.onlyEvent(t)
				for _, field := range tt.fields {
					for _, fields := range []map[string]any{entries[0], event.Fields} {
						if fields[field] != clean {
							t.Errorf("%s=%q, want %q", field, fields[field], clean)
						}
					}
				}
				for _, field := range []string{"client_ip", "request_id"} {
					got, present := event.Fields[field]
					if identifiers == "" && present {
						t.Errorf("empty %s emitted", field)
					} else if identifiers != "" && got != clean {
						t.Errorf("%s=%q, want %q", field, got, clean)
					}
					want := clean
					if identifiers == "" {
						want = ""
					}
					if entries[0][field] != want {
						t.Errorf("local %s=%q, want %q", field, entries[0][field], want)
					}
				}
			})
		}
	}
}

func TestHTTPAuditMalformedRedirect(t *testing.T) {
	for _, location := range []string{
		"https://other.vendor.example:payloadcanary/path",
		`https://other.vendor.example:payloadcanary/path?token="payloadcanary"`,
		`https://other.vendor.example:payloadcanary/path?token=\payloadcanary`,
		"/payloadcanary%zz",
	} {
		t.Run(location, func(t *testing.T) {
			origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}))
			defer origin.Close()
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := origin.Client().Do(req)
			if response != nil {
				_ = response.Body.Close()
			}
			if err == nil {
				t.Fatal("expected malformed redirect error")
			}
			t.Logf("net/http producer: %v", err)
			path := filepath.Join(t.TempDir(), "audit.log")
			logger, logErr := New("json", "file", path, true, true)
			if logErr != nil {
				t.Fatal(logErr)
			}
			t.Cleanup(logger.Close)
			sink := &collectingSink{}
			emitter := emit.NewEmitter("test-instance", sink)
			t.Cleanup(func() { _ = emitter.Close() })
			logger.SetEmitter(emitter)
			logger.LogError(LogContext{url: origin.URL}, err)
			logger.Close()
			entries := readInterceptEntries(t, path)
			if len(entries) != 1 {
				t.Fatalf("local entries=%d, want 1", len(entries))
			}
			event := sink.onlyEvent(t)
			for _, fields := range []map[string]any{entries[0], event.Fields} {
				message, ok := fields["error"].(string)
				if !ok || !strings.Contains(message, "request failed") {
					t.Errorf("error=%v, want safe redirect diagnostic", fields["error"])
				}
				if strings.Contains(message, "payloadcanary") {
					t.Errorf("payload reached error: %s", message)
				}
			}
		})
	}
}

type auditCyclicError struct{}

func (*auditCyclicError) Error() string   { return "cycle" }
func (e *auditCyclicError) Unwrap() error { return e }

type auditSliceError []error

func (auditSliceError) Error() string     { return "slice wrapper" }
func (e auditSliceError) Unwrap() []error { return e }

type auditValueError []byte

func (auditValueError) Error() string { return "ordinary value error" }

type auditSingleValueError []byte

func (auditSingleValueError) Error() string   { return "value wrapper" }
func (e auditSingleValueError) Unwrap() error { return e }

type auditURLAliasError struct{ err *url.Error }

func (e auditURLAliasError) Error() string { return e.err.Error() }
func (e auditURLAliasError) As(target any) bool {
	if p, ok := target.(**url.Error); ok {
		*p = e.err
		return true
	}
	return false
}

func TestAuditURLErrorTree(t *testing.T) {
	leaf := &url.Error{Op: "Get", URL: "https://api.vendor.example/payloadcanary", Err: errors.New("upstream unavailable")}
	var deep error = leaf
	for range 1000 {
		deep = fmt.Errorf("context: %w", errors.Join(deep))
	}
	var nilURL *url.Error
	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{"nil", nil, ""},
		{"plain", errors.New("ordinary failure"), "ordinary failure"},
		{"custom As", auditURLAliasError{leaf}, "request failed"},
		{"nil custom As", auditURLAliasError{}, "[redacted invalid error tree]"},
		{"deep", deep, "request failed"},
		{"shared subtree", errors.Join(leaf, leaf), `Get "https://api.vendor.example": request failed`},
		{"multi wrapping", fmt.Errorf("first %w; second %w", leaf, leaf), "request failed"},
		{"cycle", &auditCyclicError{}, "[redacted invalid error tree]"},
		{"URL cycle", nil, "[redacted invalid error tree]"},
		{"typed nil", nilURL, "[redacted invalid error tree]"},
		{"noncomparable wrapper", auditSliceError{leaf}, "[redacted invalid error tree]"},
		{"noncomparable single wrapper", auditSingleValueError{1}, "[redacted invalid error tree]"},
		{"noncomparable leaf", auditValueError{1}, "ordinary value error"},
		{"DNS diagnostic", &url.Error{Op: "Get", URL: leaf.URL, Err: &net.OpError{Op: "dial", Net: "tcp", Err: &net.DNSError{Name: "api.vendor.example", Err: "no such host"}}}, "DNS lookup failed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if tt.name == "URL cycle" {
				cyclic := &url.Error{Op: "Get", URL: leaf.URL}
				cyclic.Err = cyclic
				tt.err = cyclic
			}
			got := redactURLErrors(tt.err)
			if tt.err == nil {
				if got != nil {
					t.Fatal(got)
				}
				return
			}
			if got == nil || !strings.Contains(got.Error(), tt.want) {
				t.Fatalf("got %v, want %q", got, tt.want)
			}
			if strings.Contains(got.Error(), "payloadcanary") {
				t.Fatal("payload reached error")
			}
		})
	}
}

type auditCountedError struct {
	child  error
	visits *int
}

func (*auditCountedError) Error() string { return "wrapper" }
func (e *auditCountedError) Unwrap() error {
	*e.visits++
	return e.child
}

func TestAuditErrorTreeVisitsOnce(t *testing.T) {
	visits := 0
	err := errors.New("ordinary failure")
	const wrappers = 8
	for range wrappers {
		err = &auditCountedError{child: err, visits: &visits}
	}
	found, _, valid := collectURLErrors(err)
	if !valid || len(found) != 0 || visits != wrappers {
		t.Fatalf("valid=%v URL errors=%d unwrap calls=%d, want true, 0, %d", valid, len(found), visits, wrappers)
	}
}

func TestAuditRedirectCauseSurvivesLongerURL(t *testing.T) {
	// A longer URL error is replaced before a redirect failure whose Location
	// echoes that URL; the redirect's cause must still be replaced whole.
	long := "https://api.vendor.example/v1/secret/payloadcanary"
	//nolint:errorlint // net/http formats the Location parse error with %v, so it is not wrapped.
	redirect := &url.Error{Op: "Get", URL: "https://api.vendor.example/v1", Err: fmt.Errorf("failed to parse Location header %q: %v", long+"/%zz", errors.New(`invalid URL escape "%zz"`))}
	other := &url.Error{Op: "Get", URL: long, Err: errors.New("upstream unavailable")}
	for name, err := range map[string]error{
		"longer first":  errors.Join(other, redirect),
		"shorter first": errors.Join(redirect, other),
	} {
		t.Run(name, func(t *testing.T) {
			got := redactURLErrors(err).Error()
			if !strings.Contains(got, "request failed") || strings.Contains(got, "payloadcanary") || strings.Contains(got, "%zz") {
				t.Fatalf("redirect cause survived URL replacement: %q", got)
			}
		})
	}
}

type auditNaNError struct{ f float64 }

func (auditNaNError) Error() string   { return "nan" }
func (e auditNaNError) Unwrap() error { return e }

func TestAuditErrorTreeNaNIdentity(t *testing.T) {
	// A NaN field makes the value unequal to itself, so it can't be marked
	// active in the walk; it must fail closed rather than loop.
	done := make(chan bool, 1)
	go func() {
		_, _, valid := collectURLErrors(auditNaNError{math.NaN()})
		done <- valid
	}()
	select {
	case valid := <-done:
		if valid {
			t.Fatal("self-wrapping NaN error accepted")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collectURLErrors did not terminate on a NaN self-cycle")
	}
}

func TestAuditErrorTreeSharedSubtreeLinear(t *testing.T) {
	// Each level joins the level below twice; without the done mark the walk
	// takes 2^levels steps and reports the leaf repeatedly.
	leaf := &url.Error{Op: "Get", URL: "https://api.vendor.example/payloadcanary", Err: errors.New("upstream unavailable")}
	var tree error = leaf
	for range 60 {
		tree = errors.Join(tree, tree)
	}
	done := make(chan []*url.Error, 1)
	go func() {
		found, _, _ := collectURLErrors(tree)
		done <- found
	}()
	select {
	case found := <-done:
		if len(found) != 1 {
			t.Fatalf("URL errors=%d, want 1", len(found))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared subtrees were revisited")
	}
}
