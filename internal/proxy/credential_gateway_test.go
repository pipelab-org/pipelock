// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gobwas/ws"
	"github.com/gobwas/ws/wsutil"

	"github.com/luckyPipewrench/pipelock/internal/audit"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/redact"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

func TestDiscordGatewayStructuredCarrier(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
	auth := func(op int, extra string) string {
		return fmt.Sprintf(`{"op":%d,"d":{"token":%q%s}}`, op, credential, extra)
	}
	good := auth(2, `,"intents":513,"properties":{"os":"linux","browser":"library","device":"library"}`)
	const gateway = "wss://gateway.discord.gg/?v=10&encoding=json"
	for _, tc := range []struct {
		name, target, frame string
		allow               bool
	}{
		{"identify", gateway, good, true},
		{"resume", gateway, auth(6, `,"session_id":"session","seq":1337`), true},
		{"presence", gateway, auth(3, ""), false},
		{"elsewhere", gateway, `{"op":2,"d":{"presence":{"token":"` + credential + `"}}}`, false},
		{"extra activity", gateway, auth(2, `,"presence":{"activities":[{"name":"`+credential+`"}]}`), false},
		{"encoded extra", gateway, auth(2, `,"extra":"`+base64.StdEncoding.EncodeToString([]byte(credential))+`"`), false},
		{"other secret", gateway, auth(2, `,"extra":"AKIA`+strings.Repeat("A", 16)+`"`), false},
		{"duplicate op", gateway, `{"op":3,"op":2,"d":{"token":"` + credential + `"}}`, false},
		{"duplicate nested", gateway, auth(2, `,"presence":{"x":1,"x":2}`), false},
		{"escaped duplicate", gateway, `{"op":2,"d":{"token":"` + credential + `","to\u006ben":"ordinary"}}`, false},
		{"duplicate benign", gateway, `{"op":2,"d":{"token":"ordinary","token":"ordinary"}}`, false},
		{"malformed", gateway, good[:len(good)-1], false},
		{"trailing root", gateway, good + `{}`, false},
		{"non-string", gateway, `{"op":2,"d":{"token":123}}`, false},
		{"null token", gateway, `{"op":6,"d":{"token":null}}`, false},
		{"array token", gateway, `{"op":2,"d":{"token":["` + credential + `"]}}`, false},
		{"lookalike", "wss://gateway.discord.gg.evil.example/", good, false},
		{"userinfo", "wss://gateway.discord.gg@api.vendor.example/", good, false},
		{"cleartext", "ws://gateway.discord.gg/", good, false},
		{"HTTP", "https://gateway.discord.gg/", good, false},
		{"wrong route", "wss://gateway.discord.gg/api", good, false},
		{"REST host", "wss://discord.com/api", good, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relay := newCredentialAudienceWebSocketRelay(sc, cfg, tc.target)
			buf, result := relay.scanClientMessageBody(t.Context(), []byte(tc.frame))
			if result.Clean != tc.allow {
				t.Fatalf("body clean=%t want %t: %+v", result.Clean, tc.allow, result)
			}
			if tc.allow && string(buf) != tc.frame {
				t.Fatal("forwarded frame was changed")
			}
			relay = newCredentialAudienceWebSocketRelay(sc, cfg, tc.target)
			if blocked := relay.scanClientText(t.Context(), audit.NewNop(), []byte(tc.frame)); blocked == tc.allow {
				t.Fatalf("direct blocked=%t want %t", blocked, !tc.allow)
			}
		})
	}
	t.Run("binary", func(t *testing.T) {
		relay := newCredentialAudienceWebSocketRelay(sc, cfg, gateway)
		_, result := relay.scanClientMessageBodyWithSurface(t.Context(), []byte(good), "websocket_binary")
		if result.Clean {
			t.Fatal("binary payload earned JSON text carrier")
		}
	})
	t.Run("cross-message has no carrier", func(t *testing.T) {
		relay := newCredentialAudienceWebSocketRelay(sc, cfg, gateway)
		if !relay.scanClientCrossMessageText(t.Context(), audit.NewNop(), []byte(credential[:15]), []byte(credential[15:])) {
			t.Fatal("split credential passed without complete authentication frame")
		}
	})
	t.Run("server frame has no carrier", func(t *testing.T) {
		matches := sc.ScanTextForDLP(t.Context(), good).Matches
		kept, allows := sc.FilterTextDLPMatchesForDestination(matches, gateway, "websocket_frame")
		if len(kept) == 0 || len(allows) != 0 {
			t.Fatal("unqualified frame earned carrier")
		}
	})
	t.Run("control", func(t *testing.T) {
		relay := newCredentialAudienceWebSocketRelay(sc, cfg, gateway)
		relay.scanText = true
		var tail []byte
		if !relay.enforceClientControlPayload(t.Context(), audit.NewNop(), []byte(auth(2, "")), &tail) {
			t.Fatal("control payload earned JSON text carrier")
		}
	})
}

func TestProviderRouteSuppressionRemedies(t *testing.T) {
	for _, tc := range []struct{ rule, credential, target, other string }{
		{"Hugging Face Token", "hf_" + strings.Repeat("a", 34), "https://huggingface.co/org/repo/discussions", "https://huggingface.co/other/repo/discussions"},
		{"Google OAuth Token", "ya29." + strings.Repeat("a", 24), "https://www.googleapis.com/calendar/v3/users/me/calendarList", "https://www.googleapis.com/admin/directory/v1/users"},
	} {
		t.Run(tc.rule, func(t *testing.T) {
			if config.IsCoreDLPPatternName(tc.rule) {
				t.Fatal("documented remedy cannot suppress a core rule")
			}
			cfg := config.Defaults()
			cfg.Internal = nil
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			headers := map[string][]string{"Authorization": {"Bearer " + tc.credential}}
			before := scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, tc.target)
			if before == nil || before.Clean {
				t.Fatal("uncovered route must block without policy")
			}
			cfg.Suppress = []config.SuppressEntry{{Rule: tc.rule, Path: tc.target, Reason: "verified repository route"}}
			after := scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, tc.target)
			if after != nil && !after.Clean {
				t.Fatalf("documented suppression did not work: %+v", after)
			}
			other := scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, tc.other)
			if other == nil || other.Clean {
				t.Fatal("suppression widened to another route")
			}
		})
	}
}

func TestDiscordGatewayRelaySequence(t *testing.T) {
	for _, mode := range []struct{ body, redaction bool }{{false, false}, {true, false}, {true, true}} {
		bodyEnabled := mode.body
		for _, fragmented := range []bool{false, true} {
			t.Run(fmt.Sprintf("body=%t/fragmented=%t/redaction=%t", bodyEnabled, fragmented, mode.redaction), func(t *testing.T) {
				cfg := config.Defaults()
				cfg.Internal = nil
				cfg.RequestBodyScanning.Enabled = bodyEnabled
				if mode.redaction {
					cfg.Redaction = redact.Config{Enabled: true, DefaultProfile: "code", Profiles: map[string]redact.ProfileSpec{"code": {Classes: []string{string(redact.ClassAWSAccessKey)}}}, Limits: redact.DefaultLimits()}
				}
				sc := scanner.MustNew(cfg)
				defer sc.Close()
				relay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://gateway.discord.gg/?v=10&encoding=json")
				relay.scanText = true
				if mode.redaction {
					runtime, err := relay.proxy.buildRedactionRuntimeWithScanner(cfg, sc)
					if err != nil {
						t.Fatal(err)
					}
					if runtime == nil || !runtime.required {
						t.Fatal("redaction runtime was not activated")
					}
					relay.redaction = runtime
				}
				credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
				frames := []string{`{"op":1,"d":null}`, fmt.Sprintf(`{"op":2,"d":{"token":%q,"intents":513}}`, credential), fmt.Sprintf(`{"op":6,"d":{"token":%q,"session_id":"session","seq":1337}}`, credential), `{"op":1,"d":1337}`}
				var wire bytes.Buffer
				for _, frame := range frames {
					if fragmented {
						for i, part := range []string{frame[:len(frame)/2], frame[len(frame)/2:]} {
							opcode := ws.OpText
							if i == 1 {
								opcode = ws.OpContinuation
							}
							f := ws.MaskFrame(ws.Frame{Header: ws.Header{Fin: i == 1, OpCode: opcode, Length: int64(len(part))}, Payload: []byte(part)})
							if err := ws.WriteFrame(&wire, f); err != nil {
								t.Fatal(err)
							}
						}
					} else if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(frame)); err != nil {
						t.Fatal(err)
					}
				}
				source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
				sink := &receiptFrameConn{input: bytes.NewReader(nil)}
				relay.clientConn, relay.upstreamConn = source, sink
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				_, _, _, blocked := relay.clientToUpstream(ctx, cancel, time.Minute)
				if mode.redaction && fragmented {
					if !blocked {
						t.Fatal("redaction must retain its existing fragmented-message refusal")
					}
					return
				}
				if blocked {
					t.Fatal("valid Gateway authentication sequence blocked")
				}
				forwarded := bytes.NewReader(sink.output.Bytes())
				var actual []string
				for forwarded.Len() > 0 {
					f, err := ws.ReadFrame(forwarded)
					if err != nil {
						t.Fatal(err)
					}
					if f.Header.OpCode != ws.OpText {
						continue
					}
					if f.Header.Masked {
						ws.Cipher(f.Payload, f.Header.Mask, 0)
					}
					actual = append(actual, string(f.Payload))
				}
				if len(actual) != len(frames) {
					t.Fatalf("forwarded %d frames, want %d", len(actual), len(frames))
				}
				for i, frame := range frames {
					if mode.redaction {
						// The existing redactor serializes JSON even when it doesn't
						// redact a value. Authentication fields must retain their data.
						var want, got any
						if err := json.Unmarshal([]byte(frame), &want); err != nil {
							t.Fatal(err)
						}
						if err := json.Unmarshal([]byte(actual[i]), &got); err != nil {
							t.Fatal(err)
						}
						if !reflect.DeepEqual(want, got) {
							t.Fatalf("frame %d values changed: %q", i, actual[i])
						}
					} else if actual[i] != frame {
						t.Fatalf("frame %d bytes changed: %q", i, actual[i])
					}
				}
			})
		}
	}
}

func TestDiscordGatewayRelayCrossMessageCredential(t *testing.T) {
	for _, bodyEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%t", bodyEnabled), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			cfg.RequestBodyScanning.Enabled = bodyEnabled
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			relay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://gateway.discord.gg/")
			relay.scanText = true
			credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
			other := "N" + strings.Repeat("d", 23) + "." + strings.Repeat("e", 6) + "." + strings.Repeat("f", 27)
			frames := []string{fmt.Sprintf(`{"op":3,"d":{"note":%q}}`, other[:15]), fmt.Sprintf(`{"op":2,"d":{"token":%q,"note":%q}}`, credential, other[15:])}
			var wire bytes.Buffer
			for _, frame := range frames {
				if err := wsutil.WriteClientMessage(&wire, ws.OpText, []byte(frame)); err != nil {
					t.Fatal(err)
				}
			}
			source := &receiptFrameConn{input: bytes.NewReader(wire.Bytes())}
			sink := &receiptFrameConn{input: bytes.NewReader(nil)}
			relay.clientConn, relay.upstreamConn = source, sink
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			_, _, _, blocked := relay.clientToUpstream(ctx, cancel, time.Minute)
			if !blocked {
				t.Fatal("authenticated carrier masked a different cross-message credential of the same pattern")
			}
			framesOut := bytes.NewReader(sink.output.Bytes())
			forwarded := 0
			for framesOut.Len() > 0 {
				f, err := ws.ReadFrame(framesOut)
				if err != nil {
					t.Fatal(err)
				}
				if f.Header.OpCode == ws.OpText {
					forwarded++
				}
			}
			if forwarded != 1 {
				t.Fatalf("forwarded %d text frames, want only the first", forwarded)
			}
		})
	}
}

func TestHuggingFaceDownloadHeaderCarrier(t *testing.T) {
	cfg := config.Defaults()
	cfg.Internal = nil
	sc := scanner.MustNew(cfg)
	defer sc.Close()
	credential := "hf_" + strings.Repeat("a", 34)
	target := "https://huggingface.co/org/repo/resolve/main/model.bin"
	headers := map[string][]string{"Authorization": {"Bearer " + credential}}
	result := scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, target)
	if result != nil && !result.Clean {
		t.Fatalf("documented download header blocked: %+v", result)
	}
	_, body := scanRequestBody(t.Context(), BodyScanRequest{Body: strings.NewReader(`{"token":"` + credential + `"}`), ContentType: contentTypeJSON, MaxBytes: cfg.RequestBodyScanning.MaxBodyBytes, Scanner: sc, Target: target})
	if body.Clean {
		t.Fatal("download route allowed a token in the body")
	}
	headers = map[string][]string{"X-Api-Key": {credential}}
	result = scanRequestHeadersForTarget(t.Context(), headers, cfg, sc, target)
	if result == nil || result.Clean {
		t.Fatal("download route allowed an undocumented header")
	}
}

func TestDiscordGatewayOtherPatternPolicy(t *testing.T) {
	for _, suppressOther := range []bool{false, true} {
		t.Run(fmt.Sprintf("suppress_other=%t", suppressOther), func(t *testing.T) {
			cfg := config.Defaults()
			cfg.Internal = nil
			if suppressOther {
				cfg.Suppress = []config.SuppressEntry{{Rule: "Hugging Face Token", Path: "*", Reason: "accepted fixture data"}}
			}
			sc := scanner.MustNew(cfg)
			defer sc.Close()
			credential := "M" + strings.Repeat("a", 23) + "." + strings.Repeat("b", 6) + "." + strings.Repeat("c", 27)
			other := "hf_" + strings.Repeat("a", 34)
			frame := fmt.Sprintf(`{"op":2,"d":{"token":%q,"note":%q}}`, credential, other)
			relay := newCredentialAudienceWebSocketRelay(sc, cfg, "wss://gateway.discord.gg/")
			_, result := relay.scanClientMessageBody(t.Context(), []byte(frame))
			if result.Clean != suppressOther {
				t.Fatalf("other-pattern policy changed Gateway carrier: clean=%t patterns=%v", result.Clean, dlpMatchNames(result.DLPMatches))
			}
			if blocked := relay.scanClientText(t.Context(), audit.NewNop(), []byte(frame)); blocked == suppressOther {
				t.Fatalf("direct blocked=%t, want %t", blocked, !suppressOther)
			}
		})
	}
}
