// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func expectedDiagnosticVerifyCommand(port int) string {
	if port == 0 || port == defaultProxyPort {
		return "pipelock contain verify"
	}
	return "pipelock contain verify --port " + strconv.Itoa(port)
}

func TestDiagnosticVerifyRemediesPreservePort(t *testing.T) {
	for _, port := range []int{0, defaultProxyPort, 9432} {
		for _, defect := range []string{"gateway", "filesystem", "chain reader", "doorway reader", "completed request", "postconnect", "missing timing", "no counter", "before error", "after error", "no delta", "unexpected exit"} {
			t.Run(strconv.Itoa(port)+"/"+defect, func(t *testing.T) {
				out, code := "curl failed\nPLK_TIME_CONNECT=0.000000\n000", 7
				env := newDoctorEnv(t, func([]string) (string, int, error) { return out, code, nil })
				env.port = port
				check, wantStatus := checkRawEgressBlocked, statusUnknown
				switch defect {
				case "gateway":
					check, wantStatus = checkGatewayHealth, statusFail
					env.dialCtx = func(context.Context, string, string, time.Duration) (net.Conn, error) { return nil, os.ErrNotExist }
				case "filesystem":
					check, wantStatus = checkFilesystemConfinement, statusSkip
					env.filesystemProbe = func(context.Context, *probeEnv) (string, string) { return statusSkip, "requires root" }
				case "chain reader":
					check = checkManagedChainStructure
					env.chainStructure = nil
				case "doorway reader":
					check = checkManagedDoorwaySockets
					env.doorwaySockets = nil
				case "completed request":
					out, code, wantStatus = "200", 0, statusFail
				case "postconnect":
					code, wantStatus = 56, statusFail
				case "missing timing":
					out = "curl failed"
				case "no counter":
					env.dropCounter = nil
				case "before error":
					env.dropCounter = func(context.Context) (uint64, error) { return 0, os.ErrPermission }
				case "after error":
					reads := 0
					env.dropCounter = func(context.Context) (uint64, error) {
						reads++
						if reads == 1 {
							return 10, nil
						}
						return 0, os.ErrPermission
					}
				case "no delta":
					env.dropCounter = func(context.Context) (uint64, error) { return 10, nil }
				case "unexpected exit":
					code = 6
				}
				got := check(t.Context(), env)
				if got.status != wantStatus || (got.class != classInfra && wantStatus != statusSkip) || !strings.Contains(got.remediation, expectedDiagnosticVerifyCommand(port)) {
					t.Fatalf("result = %+v, want %s/infra with %q", got, wantStatus, expectedDiagnosticVerifyCommand(port))
				}
				if port == 0 || port == defaultProxyPort {
					if strings.Contains(got.remediation, "--port") {
						t.Fatalf("default advice changed: %+v", got)
					}
				}
			})
		}
	}
}

func TestDiagnosticViewerRemediesPreservePort(t *testing.T) {
	for _, port := range []int{0, defaultProxyPort, 9432} {
		for _, defect := range []string{"legacy ACL", "socket reader", "socket absent", "socket reread", "owner reader", "owner lookup", "owner parse", "owner mismatch", "runtime directory", "viewer enabled", "viewer disabled", "viewer access"} {
			t.Run(strconv.Itoa(port)+"/"+defect, func(t *testing.T) {
				root := t.TempDir()
				cfgPath := filepath.Join(root, "pipelock.yaml")
				cfg := "containment:\n  display:\n    enabled: true\n    backend: xvnc\n"
				if defect == "viewer enabled" || defect == "viewer access" {
					cfg += "    viewer:\n      enabled: true\n      operator_user: operator\n"
				}
				if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
					t.Fatal(err)
				}
				env := &doctorEnv{
					port: port, configPath: cfgPath, rfbSocketPath: filepath.Join(root, "rfb.sock"),
					stat: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o600}, nil },
					lstat: func(string) (os.FileInfo, error) {
						return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithOwner(testUID(), testGID())}, nil
					},
					lookupUser: func(string) (*user.User, error) {
						return &user.User{Uid: strconv.Itoa(int(testUID())), Gid: strconv.Itoa(int(testGID()))}, nil
					},
					readFile: func(string) ([]byte, error) { return nil, os.ErrNotExist },
				}
				check := checkDoctorDisplayRFB
				switch defect {
				case "legacy ACL":
					check = checkDoctorLegacyViewerACL
					env.agentHome = root
					env.lstat = nil
					env.stat = nil
				case "socket reader":
					env.lstat = nil
				case "socket absent":
					env.lstat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
				case "socket reread":
					reads := 0
					stat := env.lstat
					env.lstat = func(path string) (os.FileInfo, error) {
						reads++
						if reads == 2 {
							return nil, os.ErrPermission
						}
						return stat(path)
					}
				case "owner reader":
					env.lookupUser = nil
				case "owner lookup":
					env.lookupUser = func(string) (*user.User, error) { return nil, os.ErrNotExist }
				case "owner parse":
					env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "invalid"}, nil }
				case "owner mismatch":
					env.lookupUser = func(string) (*user.User, error) { return &user.User{Uid: "4000000"}, nil }
				case "runtime directory": // Socket-shaped parent fails the existing directory contract.
				case "viewer enabled", "viewer disabled":
					check = checkDoctorViewerService
				case "viewer access":
					check = checkDoctorViewerRFBAccess
				}
				got := check(t.Context(), env)
				if got.status != statusFail || got.class != classInfra || !strings.Contains(got.remediation, "`"+expectedDiagnosticInstallCommand(port)+"`") {
					t.Fatalf("result = %+v, want fail/infra with install command", got)
				}
			})
		}
	}
}

func TestDiagnosticRFBProbeRemedyPreservesPort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			cfgPath := filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(cfgPath, []byte("containment:\n  display:\n    backend: xvnc\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			doctor := &doctorEnv{
				port: port, configPath: cfgPath, rfbSocketPath: "/fixture/rfb.sock",
				readFile: func(string) ([]byte, error) {
					return []byte(" -rfbunixpath /fixture/rfb.sock -rfbunixmode 0600 -rfbport -1 "), nil
				},
				lstat: func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			}
			status, detail := probeAgentDisplayRFB(t.Context(), doctorViewerProbeEnv(doctor))
			if status != statusFail || !strings.Contains(detail, "`"+expectedDiagnosticInstallCommand(port)+"`") {
				t.Fatalf("RFB probe = %s %q", status, detail)
			}
		})
	}
}

func TestDiagnosticPublishedRecheckPreservesPort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			fx := newPublishedProbeFixture(t)
			fx.env.port = port
			fx.env.prelaunch = true
			fx.env.agentUserName = "operator"
			fx.tcp = publishedTestTCPHeader
			status, detail := fx.probe()
			if status != statusPass || !strings.Contains(detail, "`"+expectedDiagnosticVerifyCommand(port)+"`") {
				t.Fatalf("pending publication = %s %q", status, detail)
			}
		})
	}
}

func TestDiagnosticVerifyCommandPreservesPort(t *testing.T) {
	for _, port := range []int{0, defaultProxyPort, 1, 9432, 65535} {
		if got, want := verifyCommandForPort(port), expectedDiagnosticVerifyCommand(port); got != want {
			t.Fatalf("verify command = %q, want %q", got, want)
		}
	}
}

func TestDiagnosticChainAttributionRemediesPreservePort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		for _, unreadable := range []bool{false, true} {
			t.Run(strconv.Itoa(port)+"/unreadable="+strconv.FormatBool(unreadable), func(t *testing.T) {
				base := makeProbeEnv(t, func(env *probeEnv) {
					env.operatorUser, env.lookupUser, env.nftRulesPath = testOperatorUser, containTestLookup, "rules.nft"
					env.readFile = func(string) ([]byte, error) {
						return []byte("# operator=1000 pipelock-proxy=988 pipelock-agent=987 proxy-port=" + strconv.Itoa(port) + "\n"), nil
					}
					env.runCmd = func(context.Context, string, ...string) (string, int, error) {
						if unreadable {
							return "", 1, os.ErrPermission
						}
						return strings.ReplaceAll(strings.Replace(goodNFTContainmentOutput, "meta skuid 987 ip daddr", "ip daddr 192.0.2.0/24 accept\n\t\tmeta skuid 987 ip daddr", 1), "8888", strconv.Itoa(port)), 0, nil
					}
				})
				got := doctorChainStructureReader(base, &doctorEnv{port: port, agentUserName: testAgentUser})(t.Context())
				if got.status != statusUnknown || !strings.Contains(got.remediation, "`"+expectedDiagnosticVerifyCommand(port)+"`") {
					t.Fatalf("chain attribution = %+v", got)
				}
			})
		}
	}
}
