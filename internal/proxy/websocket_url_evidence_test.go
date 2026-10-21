// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/ws"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

// The scanner and the session recorder must see the same supplied URL, even
// when the upstream handshake doesn't send every URL component.
func TestWebSocketURLFindingEvidenceMatchesAdmission(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		for _, blocklist := range []bool{false, true} {
			for _, core := range []bool{false, true} {
				for _, carrier := range []string{"userinfo", "fragment", "query"} {
					if !core && carrier == "fragment" {
						continue
					}
					t.Run(fmt.Sprintf("enforce=%t/blocklist=%t/core=%t/%s", enforce, blocklist, core, carrier), func(t *testing.T) {
						var upstreamHits atomic.Int32
						upstreamSeen := make(chan struct{}, 1)
						backend := newIPv4Server(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							upstreamHits.Add(1)
							upstreamSeen <- struct{}{}
							conn, _, _, err := ws.UpgradeHTTP(r, w)
							if err == nil {
								_ = conn.Close()
							}
						}))
						defer backend.Close()
						addr, p, cleanup := setupWSProxyDefaultWithProxy(t, func(cfg *config.Config) {
							adaptiveWarnTransportConfig(cfg)
							cfg.Enforce = &enforce
							if !blocklist {
								cfg.FetchProxy.Monitoring.Blocklist = nil
							}
						})
						defer cleanup()
						target, err := url.Parse(strings.Replace(backend.URL, "http://", "ws://", 1))
						if err != nil {
							t.Fatal(err)
						}
						value := "ordinary-value"
						if core {
							value = "gh" + "p_" + strings.Repeat("aB3c", 9)
						}
						switch carrier {
						case "userinfo":
							target.User = url.UserPassword("user", value)
						case "fragment":
							target.Fragment = value
						case "query":
							target.RawQuery = "value=" + value
						}
						conn, dialErr := dialWSConnToTarget(addr, target.String())
						if conn != nil {
							defer func() { _ = conn.Close() }()
						}
						wantBlocked := core || (enforce && blocklist)
						if wantBlocked {
							if dialErr == nil || !strings.Contains(dialErr.Error(), "403") {
								t.Fatalf("want 403, got %v", dialErr)
							}
							if hits := upstreamHits.Load(); hits != 0 {
								t.Fatalf("refused request reached upstream %d times", hits)
							}
						} else {
							if dialErr != nil {
								t.Fatalf("allowed handshake: %v", dialErr)
							}
							select {
							case <-upstreamSeen:
							case <-time.After(5 * time.Second):
								t.Fatal("allowed handshake did not reach upstream")
							}
						}
						snapshots := p.sessionMgrPtr.Load().Snapshot()
						if len(snapshots) != 1 {
							t.Fatalf("sessions=%d", len(snapshots))
						}
						sess := p.sessionMgrPtr.Load().GetOrCreate(snapshots[0].Key)
						if !wantBlocked && sess.ThreatScore() != 0 {
							t.Fatalf("delivered warning scored %.1f points", sess.ThreatScore())
						}
						events := sess.RecentEvents()
						if !core && !blocklist {
							if len(events) != 0 {
								t.Fatalf("clean URL produced evidence: %+v", events)
							}
							return
						}
						if len(events) != 1 {
							t.Fatalf("want one finding, got %+v", events)
						}
						wantKind, wantSeverity := "anomaly", config.SeverityWarn
						if wantBlocked {
							wantKind, wantSeverity = config.ActionBlock, config.SeverityCritical
						}
						if e := events[0]; e.Kind != wantKind || e.Severity != wantSeverity {
							t.Fatalf("verdict blocked=%t, evidence=%+v", wantBlocked, e)
						}
					})
				}
			}
		}
	}
}
