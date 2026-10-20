// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package contain

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDiagnosticRuntimeSocketRemediesPreservePort(t *testing.T) {
	for _, port := range []int{defaultProxyPort, 9432} {
		for _, defect := range []string{"missing wrapper", "unreadable wrapper", "drifted wrapper", "unusable declaration", "unreadable config", "missing masks", "missing bind", "missing readers", "unreadable declaration", "unreadable masks", "unreadable bind"} {
			t.Run(strconv.Itoa(port)+"/"+defect, func(t *testing.T) {
				env := &doctorEnv{port: port, wrapperDir: t.TempDir()}
				wrapper := renderContainedLaunchWrapper(&installEnv{wrapperDir: env.wrapperDir, networkNamespaceUnitPath: containedNetworkNamespaceUnit})
				if defect == "unreadable config" {
					env.configPath = filepath.Join(t.TempDir(), "pipelock.yaml")
					if err := os.WriteFile(env.configPath, []byte("[invalid"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				env.readFile = func(path string) ([]byte, error) {
					if path == filepath.Join(env.wrapperDir, "plk-contained-launch") {
						switch defect {
						case "missing wrapper":
							return nil, os.ErrNotExist
						case "unreadable wrapper":
							return nil, os.ErrPermission
						case "drifted wrapper":
							return []byte("drifted"), nil
						}
						return []byte(wrapper), nil
					}
					if defect == "unreadable declaration" {
						return nil, os.ErrPermission
					}
					if defect == "unusable declaration" {
						return []byte("containment:\n  loopback_services: invalid\n"), nil
					}
					return []byte("{}"), nil
				}
				env.runCmd = func(_ context.Context, name string, args ...string) (string, int, error) {
					if name != "systemctl" || len(args) != 4 || args[0] != "show" || args[3] != "--value" {
						t.Fatalf("diagnostic attempted unexpected command: %s %v", name, args)
					}
					if args[2] == "--property=TemporaryFileSystem" {
						if defect == "unreadable masks" {
							return "", 1, os.ErrPermission
						}
						if defect == "missing masks" {
							return "", 0, nil
						}
						return strings.Join(runtimeSocketTemporaryFileSystems(), " "), 0, nil
					}
					if args[2] != "--property=BindReadOnlyPaths" {
						t.Fatalf("unexpected property: %v", args)
					}
					if defect == "unreadable bind" {
						return "", 1, os.ErrPermission
					}
					return "", 0, nil
				}
				if defect == "missing readers" {
					env.readFile = nil
				}
				got := probeDoctorRuntimeSockets(t.Context(), env)
				wantStatus := statusFail
				wantCommand := expectedDiagnosticInstallCommand(port)
				switch defect {
				case "missing readers", "unreadable declaration", "unreadable masks", "unreadable bind":
					wantStatus = statusUnknown
					wantCommand = expectedDiagnosticDoctorCommand(port)
				}
				if defect == "unreadable wrapper" || defect == "unreadable config" {
					wantStatus = statusUnknown
				}
				if got.status != wantStatus || !strings.HasSuffix(got.remediation, "rerun `"+wantCommand+"`") {
					t.Fatalf("runtime socket result = %+v, want %s and selected command port", got, wantStatus)
				}
			})
		}
	}
}
