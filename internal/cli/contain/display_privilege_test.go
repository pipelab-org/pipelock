// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestDisplayInspectionPrivilegeDiagnostics(t *testing.T) {
	for _, tc := range []struct{ name, doctorStatus, verifyStatus string }{
		{"healthy", statusPass, statusPass},
		{"rule read denied", statusUnknown, statusUnknown},
		{"rule stat denied", statusUnknown, statusUnknown},
		{"runtime stat denied", statusUnknown, statusUnknown},
		{"socket stat denied", statusUnknown, statusUnknown},
		{"socket owner stat denied", statusUnknown, statusPass},
		{"unit read denied", statusPass, statusUnknown},
		{"missing rule", statusFail, statusFail},
		{"unsafe rule", statusFail, statusFail},
		{"unsafe unreadable rule", statusFail, statusFail},
		{"foreign rule", statusFail, statusFail},
		{"drifted rule", statusFail, statusFail},
		{"rule read I/O error", statusFail, statusFail},
		{"unsafe runtime", statusFail, statusFail},
		{"missing runtime", statusFail, statusFail},
		{"missing socket", statusFail, statusFail},
		{"missing unit", statusPass, statusFail},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			if _, err := stepProvisionDisplayRuntime().apply(t.Context(), env); err != nil {
				t.Fatal(err)
			}
			env.displayConfig = config.ContainmentDisplay{Backend: "xvnc"}
			if err := os.WriteFile(env.displayUnitPath, []byte(renderAgentDisplayUnit(env)), 0o600); err != nil {
				t.Fatal(err)
			}
			originalStat, originalRead := env.lstat, env.readFile
			socketStats := 0
			stat := func(path string) (os.FileInfo, error) {
				switch {
				case path == env.displayTmpfilesPath:
					switch tc.name {
					case "rule stat denied":
						return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
					case "missing rule":
						return nil, os.ErrNotExist
					case "unsafe rule", "unsafe unreadable rule":
						return fakeFileInfo{mode: 0o644, sys: fakeFileSysWithOwner(0, 0)}, nil
					}
				case path == filepath.Dir(env.rfbSocketPath):
					switch tc.name {
					case "runtime stat denied":
						return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
					case "missing runtime":
						return nil, os.ErrNotExist
					case "unsafe runtime":
						return fakeFileInfo{mode: os.ModeDir | 0o755, sys: fakeFileSysWithOwner(0, 456)}, nil
					}
				case path == env.rfbSocketPath:
					socketStats++
					switch tc.name {
					case "socket stat denied":
						return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
					case "socket owner stat denied":
						if socketStats == 2 {
							return nil, &os.PathError{Op: "lstat", Path: path, Err: os.ErrPermission}
						}
					case "missing socket":
						return nil, os.ErrNotExist
					}
					return fakeFileInfo{mode: os.ModeSocket | 0o600, sys: fakeFileSysWithOwner(123, 456)}, nil
				}
				return originalStat(path)
			}
			read := func(path string) ([]byte, error) {
				if path == env.displayTmpfilesPath {
					switch tc.name {
					case "rule read denied", "unsafe unreadable rule":
						return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
					case "rule read I/O error":
						return nil, errors.New("fixture I/O failure")
					case "foreign rule":
						return []byte("# unmanaged\n"), nil
					case "drifted rule":
						return []byte(displayUnitMarker + "\nd /run/wrong 0730 root root - -\n"), nil
					}
				}
				if path == env.displayUnitPath {
					if tc.name == "unit read denied" {
						return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
					}
					if tc.name == "missing unit" {
						return nil, os.ErrNotExist
					}
				}
				return originalRead(path)
			}
			probe := &probeEnv{configPath: managedPipelockConfigPath(env), displayUnitPath: env.displayUnitPath, displayTmpfilesPath: env.displayTmpfilesPath, rfbSocketPath: env.rfbSocketPath, agentUserName: env.agentUserName, lookupUser: env.lookupUser, readFile: read, lstat: stat}
			doctor := &doctorEnv{configPath: probe.configPath, displayTmpfilesPath: probe.displayTmpfilesPath, rfbSocketPath: probe.rfbSocketPath, agentUserName: probe.agentUserName, lookupUser: probe.lookupUser, lstat: stat, readFile: read, stat: func(string) (os.FileInfo, error) { return fakeFileInfo{mode: 0o755}, nil }}
			got := checkDoctorDisplayRFB(context.Background(), doctor)
			status, detail := probeAgentDisplayRFB(context.Background(), probe)
			t.Logf("doctor=%s verify=%s detail=%s remedy=%s", got.status, status, detail, got.remediation)
			if got.status != tc.doctorStatus || status != tc.verifyStatus {
				t.Fatalf("doctor=%+v verify=(%s,%s), want=(%s,%s)", got, status, detail, tc.doctorStatus, tc.verifyStatus)
			}
			if tc.verifyStatus == statusUnknown && !strings.Contains(detail, "as root") {
				t.Errorf("unknown verification lacks privilege remedy: %s", detail)
			}
			if tc.doctorStatus == statusUnknown && !strings.Contains(got.remediation, "as root") {
				t.Errorf("unknown doctor lacks privilege remedy: %+v", got)
			}
		})
	}
}

func TestDisplayDisabledRuleRemovalValidatesParents(t *testing.T) {
	for _, unsafe := range []bool{false, true} {
		t.Run(map[bool]string{false: "valid parent", true: "unsafe parent"}[unsafe], func(t *testing.T) {
			env, _ := displayRuntimeTestEnv(t)
			if _, err := stepProvisionDisplayRuntime().apply(t.Context(), env); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(managedPipelockConfigPath(env), []byte("containment:\n  display:\n    enabled: false\n    backend: xvnc\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			originalStat, originalRemove := env.lstat, env.removeFile
			if unsafe {
				env.lstat = func(path string) (os.FileInfo, error) {
					if path == filepath.Dir(env.displayTmpfilesPath) {
						return fakeFileInfo{mode: os.ModeDir | 0o777, sys: fakeFileSysWithOwner(0, 0)}, nil
					}
					return originalStat(path)
				}
			}
			removed := false
			env.removeFile = func(path string) error {
				if path == env.displayTmpfilesPath {
					removed = true
				}
				return originalRemove(path)
			}
			changed, err := stepProvisionDisplayRuntime().apply(t.Context(), env)
			t.Logf("changed=%v removed=%v err=%v", changed, removed, err)
			if unsafe {
				if changed || removed || err == nil || !strings.Contains(err.Error(), "root-controlled") {
					t.Fatalf("unsafe parent allowed unlink: changed=%v removed=%v err=%v", changed, removed, err)
				}
			} else if err != nil || !changed || !removed {
				t.Fatalf("valid disabled path did not remove rule: changed=%v removed=%v err=%v", changed, removed, err)
			}
		})
	}
}
