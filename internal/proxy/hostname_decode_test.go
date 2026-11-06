// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestHostnameLabelDecodingTransports(t *testing.T) {
	addr, cleanup := setupForwardProxy(t, queryViewsProxyConfig)
	defer cleanup()
	credential := queryViewsCredential()
	for encoding, encoded := range map[string]string{
		"hex":       hex.EncodeToString([]byte(credential)),
		"lower32":   strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(credential))),
		"base32hex": strings.ToLower(base32.HexEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(credential))),
		"base64url": base64.RawURLEncoding.EncodeToString([]byte(credential)),
	} {
		for _, width := range []int{4, 7, 63} {
			var labels []string
			for start := 0; start < len(encoded); start += width {
				labels = append(labels, encoded[start:min(start+width, len(encoded))])
			}
			host := strings.Join(labels, ".") + ".vendor.example"
			for _, route := range []string{"fetch", "forward", "connect"} {
				t.Run(fmt.Sprintf("%s/%d/%s", encoding, width, route), func(t *testing.T) {
					method, target, authority := http.MethodGet, "http://"+host+"/", host
					switch route {
					case "fetch":
						target = "/fetch?url=" + url.QueryEscape("https://"+host+"/")
						authority = addr
					case "connect":
						method, target, authority = http.MethodConnect, host+":443", host+":443"
					}
					conn := dialProxy(t, addr)
					defer func() { _ = conn.Close() }()
					if _, err := fmt.Fprintf(conn, "%s %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", method, target, authority); err != nil {
						t.Fatal(err)
					}
					resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if resp.StatusCode != http.StatusForbidden || !strings.Contains(strings.ToLower(string(body)), "dlp") {
						t.Fatalf("status=%d, expected DLP rejection", resp.StatusCode)
					}
				})
			}
		}
	}
}
