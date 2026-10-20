// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func TestDoorwayInstallRemedyPreservesPort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 1, 9432, 65535} {
		for _, condition := range []string{"missing definition", "drifted definition", "missing socket", "missing relay", "missing forwarder", "invalid relay", "unexpected pathname", "noncanonical unit"} {
			t.Run(strconv.Itoa(port)+"/"+condition, func(t *testing.T) {
				env := diagnosticDoorwayEnv(nil)
				env.port = port
				switch condition {
				case "missing definition":
					env.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
				case "drifted definition":
					env.readFile = func(string) ([]byte, error) { return []byte("drifted"), nil }
				case "missing socket", "missing relay", "missing forwarder", "invalid relay":
					unit := testDoorwayProxySocket
					switch condition {
					case "missing relay", "invalid relay":
						unit = testDoorwayProxyRelay
					case "missing forwarder":
						unit = containedNamespaceForwarderUnit
					}
					state := systemctlNotFound
					if condition == "invalid relay" {
						state = "bad"
					}
					env = diagnosticDoorwayEnv(map[string]fakeUnitState{unit: {state, "inactive"}})
					env.port = port
				case "unexpected pathname":
					env.lstat = func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o600}, nil }
				case "noncanonical unit":
					env.proxyForwarderSocketPath = "/etc/systemd/system/unexpected.socket"
				}
				want := "pipelock contain install"
				if port != defaultProxyPort {
					want += " --proxy-port " + strconv.Itoa(port)
				}
				got := doctorDoorwayState(context.Background(), env, nil)
				if got.status != statusFail || got.class != classInfra || !strings.Contains(got.remediation, "`"+want+"`") {
					t.Fatalf("doctor result = %+v, want fail/infra with command %q", got, want)
				}
				status, detail := probeManagedDoorwaySockets(context.Background(), env, nil)
				if status != statusFail || !strings.Contains(detail, "`"+want+"`") {
					t.Fatalf("verify result = %s %q, want fail with command %q", status, detail, want)
				}
			})
		}
	}
}

func expectedDiagnosticInstallCommand(port int) string {
	if port == 0 || port == defaultProxyPort {
		return "pipelock contain install"
	}
	return "pipelock contain install --proxy-port " + strconv.Itoa(port)
}

func TestDiagnosticInstallCommandPreservesPort(t *testing.T) {
	for _, port := range []int{0, defaultProxyPort, 1, 9432, 65535} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			want := expectedDiagnosticInstallCommand(port)
			if got := installCommandForPort(port); got != want {
				t.Fatalf("install command = %q, want %q", got, want)
			}
			if got := installRemedyForPort(port); got != "rerun `"+want+"`" {
				t.Fatalf("install remedy = %q", got)
			}
		})
	}
}

func TestDoorwayCombinedInstallRemedyPreservesPort(t *testing.T) {
	env := diagnosticDoorwayEnv(map[string]fakeUnitState{testDoorwayProxyRelay: {"bad", systemctlFailed}})
	env.port = 9432
	env.lstat = func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o600}, nil }
	got := doctorDoorwayState(t.Context(), env, nil)
	want := "rerun `pipelock contain install --proxy-port 9432`"
	if got.status != statusFail || got.class != classInfra || strings.Count(got.remediation, want) != 2 ||
		!strings.Contains(got.detail, "invalid or unreadable") || !strings.Contains(got.detail, "not a socket") {
		t.Fatalf("combined result = %+v", got)
	}
	for _, remedy := range []string{
		namespaceForwarderRemedy(containedNamespaceForwarderUnit, systemctlNotFound, "inactive", env.port),
		doorwayRecoveryRemedy(managedDoorway{}, doorwayUnitState{}, doorwayUnitState{}, doorwayUnitState{enabled: systemctlNotFound}, env.port),
	} {
		if !strings.Contains(remedy, want) {
			t.Fatalf("missing forwarder remedy = %q", remedy)
		}
	}
}

func TestDiagnosticCommandsPreserveInstallPort(t *testing.T) {
	origDoctor, origVerify := doctorEnvFactory, verifyEnvFactory
	t.Cleanup(func() { doctorEnvFactory, verifyEnvFactory = origDoctor, origVerify })
	for _, diagnostic := range []string{"doctor", "verify"} {
		for _, port := range []int{defaultProxyPort, 9432} {
			for _, jsonOutput := range []bool{false, true} {
				t.Run(diagnostic+"/"+strconv.Itoa(port)+"/json="+strconv.FormatBool(jsonOutput), func(t *testing.T) {
					var selectedPort func() int
					doctorEnvFactory = func() *doctorEnv {
						env := allPassDoctorEnv(t)
						base := diagnosticDoorwayEnv(nil)
						base.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
						env.doorwaySockets = doctorDoorwaySocketReader(base, env)
						selectedPort = func() int { return env.port }
						return env
					}
					verifyEnvFactory = func() *probeEnv {
						env := allPassEnv(t)
						read := env.readFile
						env.readFile = func(path string) ([]byte, error) {
							if path == env.proxyForwarderSocketPath {
								return nil, os.ErrNotExist
							}
							return read(path)
						}
						env.networkNamespaceProbe = func(ctx context.Context, probe *probeEnv) (string, string) {
							return probeManagedDoorwaySockets(ctx, probe, nil)
						}
						selectedPort = func() int { return env.port }
						return env
					}
					cmd := Cmd()
					args := []string{diagnostic}
					if port != defaultProxyPort {
						args = append(args, "--port", strconv.Itoa(port))
					}
					if jsonOutput {
						args = append(args, "--json")
					}
					var output bytes.Buffer
					cmd.SetOut(&output)
					cmd.SetErr(&output)
					cmd.SetArgs(args)
					err := cmd.Execute()
					want := "rerun `" + expectedDiagnosticInstallCommand(port) + "`"
					if cliutil.ExitCodeOf(err) != cliutil.ExitGeneral || !strings.Contains(output.String(), want) {
						t.Fatalf("command error = %v, output = %s; want failing diagnostic with %q", err, output.String(), want)
					}
					if selectedPort == nil || selectedPort() != port {
						t.Fatalf("command did not select port %d", port)
					}
				})
			}
		}
	}
}

func TestDiagnosticCommandsRejectInvalidInstallPort(t *testing.T) {
	origDoctor, origVerify := doctorEnvFactory, verifyEnvFactory
	t.Cleanup(func() { doctorEnvFactory, verifyEnvFactory = origDoctor, origVerify })
	doctorEnvFactory = func() *doctorEnv { t.Fatal("invalid port reached doctor probes"); return nil }
	verifyEnvFactory = func() *probeEnv { t.Fatal("invalid port reached verify probes"); return nil }
	for _, diagnostic := range []string{"doctor", "verify"} {
		for _, port := range []string{"0", "-1", "65536", "9432;false"} {
			t.Run(diagnostic+"/"+port, func(t *testing.T) {
				cmd := Cmd()
				var output bytes.Buffer
				cmd.SetOut(&output)
				cmd.SetErr(&output)
				cmd.SetArgs([]string{diagnostic, "--port", port})
				if err := cmd.Execute(); err == nil || strings.Contains(output.String(), "contain install") {
					t.Fatalf("invalid port error = %v, output = %q", err, output.String())
				}
			})
		}
	}
}

func TestDiagnosticSiblingInstallRemediesPreservePort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			want := expectedDiagnosticInstallCommand(port)
			env := newDoctorEnv(t, func([]string) (string, int, error) { return "sudo: unknown user pipelock-agent", 1, nil })
			env.port = port
			for _, check := range []func(context.Context, *doctorEnv) doctorResult{checkCurlThroughProxy, checkPythonThroughProxy, checkNodeThroughProxy, checkDNSFailure, checkRawEgressBlocked} {
				result := check(t.Context(), env)
				if result.status != statusSkip || result.remediation != "run `"+want+"` first" {
					t.Fatalf("missing agent result = %+v", result)
				}
			}
			env.stat = func(string) (os.FileInfo, error) { return nil, os.ErrNotExist }
			if got := checkNodeThroughProxy(t.Context(), env); got.status != statusSkip || got.remediation != "re-run `"+want+"` to write the shim" {
				t.Fatalf("missing shim result = %+v", got)
			}
			probe := makeProbeEnv(t)
			probe.port = port
			probe.readFile = func(string) ([]byte, error) { return nil, os.ErrNotExist }
			if _, err := loadProbeConfig(probe); err == nil || !strings.Contains(err.Error(), "`"+want+"`") {
				t.Fatalf("missing config error = %v", err)
			}
			status, detail := probeCurrentCAExport(t.Context(), probe)
			if status != statusFail || !strings.Contains(detail, "run `"+want+"` or `pipelock contain ca-refresh`") {
				t.Fatalf("missing CA result = %s %q", status, detail)
			}
			probe.lookPath = func(string) (string, error) { return "", exec.ErrNotFound }
			status, detail = probeBrowserCATrustState(t.Context(), probe)
			if status != statusFail || !strings.Contains(detail, "rerun "+want+" so") {
				t.Fatalf("missing certutil result = %s %q", status, detail)
			}
			probe.networkNamespaceUnitPath = "/fixture/pipelock-agent-netns.service"
			probe.readFile = func(string) ([]byte, error) { return []byte("drifted"), nil }
			status, detail = probeAgentNetworkNamespaceForServices(t.Context(), probe, verifyLoopbackDeclaration{})
			if status != statusFail || !strings.HasSuffix(detail, "rerun `"+want+"`") {
				t.Fatalf("namespace drift result = %s %q", status, detail)
			}
			for _, states := range [][3]string{{systemctlMasked, systemctlActive, "static"}, {"disabled", systemctlActive, "static"}, {systemctlEnabled, "inactive", "static"}, {systemctlEnabled, systemctlActive, systemctlMasked}} {
				expiry := newExpiryProbeEnv(t, expiryTimerReply{out: states[0]}, expiryTimerReply{out: states[1]}, expiryTimerReply{out: states[2]})
				expiry.port = port
				if err := verifyNFTExpiryTimer(t.Context(), expiry); err == nil || !strings.HasSuffix(err.Error(), "rerun `"+want+"`") {
					t.Fatalf("expiry repair error = %v", err)
				}
			}
		})
	}
}

func TestDiagnosticLaunchEnvRemediesPreservePort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		canonical := canonicalLaunchScript(port, defaultCABundlePath)
		for _, body := range []string{
			"exec env HOME=/home/agent \"$TARGET\"\n",
			strings.Replace(canonical, "    SHELL=/bin/bash", "    SHELL=/bin/bash ; false", 1),
			canonical + canonical,
			strings.Replace(canonical, "    PATH=", "    HTTPS_PROXY=http://127.0.0.1:9 \\\n    PATH=", 1),
			strings.Replace(canonical, "    NO_PROXY=", "    NOT_PROXY=", 1),
			strings.Replace(canonical, "HTTPS_PROXY="+proxyURLFor(port), "HTTPS_PROXY=http://127.0.0.1:9", 1),
		} {
			env := makeProbeEnv(t)
			env.port, env.caBundlePath = port, defaultCABundlePath
			if err := os.WriteFile(env.launchPath, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			status, detail := probeLaunchEnvAllowList(t.Context(), env)
			if status != statusFail || !strings.HasSuffix(detail, "reinstall with `"+expectedDiagnosticInstallCommand(port)+"`") {
				t.Fatalf("launcher result = %s %q", status, detail)
			}
		}
	}
}

func expectedDiagnosticDoctorCommand(port int) string {
	if port == 0 || port == defaultProxyPort {
		return "pipelock contain doctor"
	}
	return "pipelock contain doctor --port " + strconv.Itoa(port)
}

func TestDiagnosticDisabledForwardingRemedyPreservesPort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 1, 9432, 65535} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			env := allPassDoctorEnv(t)
			env.port = port
			env.configPath = filepath.Join(t.TempDir(), "pipelock.yaml")
			if err := os.WriteFile(env.configPath, []byte("forward_proxy:\n  enabled: false\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			got, done := checkDisabledForwardProxy(env)
			want := "set forward_proxy.enabled: true in " + env.configPath + " and rerun `" + expectedDiagnosticInstallCommand(port) + "`, then rerun `" + expectedDiagnosticDoctorCommand(port) + "`"
			if !done || got.status != statusFail || got.class != classInfra || got.remediation != want {
				t.Fatalf("disabled forwarding result = %+v, done=%t; want remediation %q", got, done, want)
			}
		})
	}
}

func TestDiagnosticDoctorCommandPreservesPort(t *testing.T) {
	for _, port := range []int{0, defaultProxyPort, 1, 9432, 65535} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			if got, want := doctorCommandForPort(port), expectedDiagnosticDoctorCommand(port); got != want {
				t.Fatalf("doctor command = %q, want %q", got, want)
			}
		})
	}
}

func TestDiagnosticDoctorRechecksPreservePort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		t.Run(strconv.Itoa(port), func(t *testing.T) {
			base := diagnosticDoorwayEnv(nil)
			base.readFile = func(string) ([]byte, error) { return nil, os.ErrPermission }
			got := doctorDoorwaySocketReader(base, &doctorEnv{port: port})(t.Context())
			want := "restore access to the managed containment configuration and rerun `" + expectedDiagnosticDoctorCommand(port) + "`"
			if got.status != statusUnknown || got.class != classInfra || got.remediation != want {
				t.Fatalf("declaration recheck = %+v; want %q", got, want)
			}
			for _, input := range []struct {
				out string
				err error
			}{{err: os.ErrPermission}, {out: "sudo: a password is required"}} {
				got, done := classifyAgentRun(input.out, input.err, "curl", port)
				want := "re-run as root: sudo " + expectedDiagnosticDoctorCommand(port)
				if !done || got.status != statusSkip || got.remediation != want {
					t.Fatalf("root recheck = %+v, done=%t; want %q", got, done, want)
				}
			}
		})
	}
}

func TestDiagnosticDefinitionReadFailurePreservesPort(t *testing.T) {
	env := diagnosticDoorwayEnv(nil)
	env.port = 9432
	env.readFile = func(string) ([]byte, error) { return nil, errors.New("synthetic read failure") }
	got := doctorDoorwayState(t.Context(), env, nil)
	if got.status != statusFail || got.remediation != "rerun `pipelock contain install --proxy-port 9432`" || !strings.Contains(got.detail, "synthetic read failure") {
		t.Fatalf("definition read result = %+v", got)
	}
}

func TestDiagnosticSiblingReadFailuresPreservePort(t *testing.T) {
	const port = 9432
	want := "rerun `pipelock contain install --proxy-port 9432`"
	base := diagnosticDoorwayEnv(nil)
	base.readFile = func(string) ([]byte, error) { return []byte("containment:\n  loopback_services: invalid\n"), nil }
	if got := doctorDoorwaySocketReader(base, &doctorEnv{port: port})(t.Context()); got.status != statusFail || !strings.HasSuffix(got.remediation, want) {
		t.Fatalf("unusable declaration = %+v", got)
	}
	env := newDoctorEnv(t, func([]string) (string, int, error) { return "connection refused", 7, nil })
	env.port = port
	env.dropCounter = func(context.Context) (uint64, error) {
		return 0, &containmentBypassError{rule: "meta skuid 987 accept"}
	}
	if got := checkRawEgressBlocked(t.Context(), env); got.status != statusFail || !strings.HasSuffix(got.remediation, want) {
		t.Fatalf("definite boundary failure = %+v", got)
	}
	base = diagnosticDoorwayEnv(map[string]fakeUnitState{
		testDoorwayProxySocket:          {systemctlEnabled, "inactive"},
		containedNamespaceForwarderUnit: {"disabled", "inactive"},
	})
	base.port = port
	run := base.runCmd
	base.runCmd = func(ctx context.Context, name string, args ...string) (string, int, error) {
		if len(args) == 2 && args[1] == testDoorwayProxyRelay {
			return "", -1, os.ErrPermission
		}
		return run(ctx, name, args...)
	}
	got := doctorDoorwayState(t.Context(), base, nil)
	if got.status != statusFail || !strings.Contains(got.remediation, "systemctl enable --now "+containedNamespaceForwarderUnit) || strings.Contains(got.remediation, "contain install") {
		t.Fatalf("unreadable relay with definite forwarder failure = %+v", got)
	}
}

func TestDiagnosticBrowserCertutilDisappearancePreservesPort(t *testing.T) {
	installed, _ := newBrowserCAEnv(t)
	if _, err := establishAgentBrowserCATrust(t.Context(), installed); err != nil {
		t.Fatal(err)
	}
	probe := &probeEnv{
		port: 9432, agentHome: installed.agentHome, caExportPath: installed.caExportPath,
		platformFamily: installed.platformFamily, lookPath: installed.lookPath,
		stat: os.Stat, readFile: installed.readFile,
		runCmd: func(context.Context, string, ...string) (string, int, error) { return "", -1, exec.ErrNotFound },
	}
	status, detail := probeBrowserCATrustState(t.Context(), probe)
	if status != statusFail || !strings.Contains(detail, "rerun pipelock contain install --proxy-port 9432 so") {
		t.Fatalf("certutil disappeared after lookup = %s %q", status, detail)
	}
	if err := missingCertutilError(installed.platformFamily); !errors.Is(err, errCertutilMissing) || strings.Contains(err.Error(), "--proxy-port") {
		t.Fatalf("default installer certutil error changed: %v", err)
	}
}
