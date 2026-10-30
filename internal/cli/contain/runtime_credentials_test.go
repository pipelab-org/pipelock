// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package contain

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"testing/fstest"
)

const credentialTestUnit = "agent-worker.service"

func credentialRuntimeFixture(unit, filesystem string) netnsAssertEnv {
	path := "/run/credentials/" + unit
	tree := fstest.MapFS{
		"pipelock-contain/agent-netns.id":  &fstest.MapFile{Mode: 0o600},
		"credentials/" + unit + "/api-key": &fstest.MapFile{Mode: 0o400},
	}
	mounts := managedRuntimeMountFixture + "23 20 0:202 / /run/credentials ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n" + fmt.Sprintf("24 23 0:203 / %s ro,nosuid,nodev,noexec - %s %s rw\n", strings.ReplaceAll(path, `\`, `\134`), filesystem, filesystem) + fmt.Sprintf("26 20 0:50 %s /run/systemd/incoming ro - tmpfs tmpfs rw\n", strings.ReplaceAll(systemdPropagationRoot+unit, `\`, `\134`))
	env := defaultNetnsAssertEnv()
	env.readFile = func(path string) ([]byte, error) {
		switch path {
		case "/proc/self/mountinfo":
			return []byte(mounts), nil
		case "/proc/self/cgroup":
			return []byte("0::/system.slice/" + unit + "\n"), nil
		default:
			return managedRuntimeFixtureReadFile(path)
		}
	}
	env.readDir = func(path string) ([]os.DirEntry, error) {
		name := strings.TrimPrefix(path, "/run/")
		if path == "/run" {
			name = "."
		}
		return tree.ReadDir(name)
	}
	env.lstat = func(path string) (os.FileInfo, error) {
		mode := os.ModeDir | 0o555
		if path == systemdIncomingPath {
			mode = os.ModeDir | 0o600
		}
		if path == "/run/credentials" {
			mode = os.ModeDir | 0o755
		}
		if path == "/run/credentials/"+unit+"/api-key" {
			mode = 0o400
		}
		return fakeFileInfo{mode: mode, sys: fakeFileSysWithUID(0)}, nil
	}
	return env
}

func TestRuntimeMountSystemdCredentials(t *testing.T) {
	for _, tc := range []struct{ name, unit, filesystem, cgroupUnit string }{
		{"LoadCredential", credentialTestUnit, "tmpfs", credentialTestUnit},
		{"LoadCredentialEncrypted", credentialTestUnit, "ramfs", credentialTestUnit},
		{"template instance", "agent-worker@one.service", "tmpfs", "agent-worker@one.service"},
		{"escaped instance", `agent-worker@one\x2dtwo.service`, "tmpfs", `agent-worker@one\x2dtwo.service`},
		{"leading underscore unit", "_agent-worker.service", "tmpfs", "__agent-worker.service"},
		{"reserved cgroup unit", "cgroup.worker.service", "tmpfs", "_cgroup.worker.service"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := credentialRuntimeFixture(tc.unit, tc.filesystem)
			read := env.readFile
			env.readFile = func(name string) ([]byte, error) {
				if name == "/proc/self/cgroup" {
					return []byte("0::/system.slice/" + tc.cgroupUnit + "\n"), nil
				}
				return read(name)
			}
			if got := processSystemdUnit(env.readFile, "/proc/self/cgroup"); got != tc.unit {
				t.Fatalf("unit identity = %q, want %q", got, tc.unit)
			}
			if err := assertManagedRuntimeMounts(env); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func replaceCredentialMountEvidence(env *netnsAssertEnv, old, replacement string) {
	read := env.readFile
	env.readFile = func(path string) ([]byte, error) {
		data, err := read(path)
		if path == "/proc/self/mountinfo" {
			data = []byte(strings.ReplaceAll(string(data), old, replacement))
		}
		return data, err
	}
}

func credentialStatOverride(env *netnsAssertEnv, path string, mode os.FileMode, uid uint32) {
	stat := env.lstat
	env.lstat = func(name string) (os.FileInfo, error) {
		if name == path {
			return fakeFileInfo{mode: mode, sys: fakeFileSysWithUID(uid)}, nil
		}
		return stat(name)
	}
}

func credentialReadFailure(env *netnsAssertEnv, path string) {
	read := env.readFile
	env.readFile = func(name string) ([]byte, error) {
		if name == path {
			return nil, os.ErrPermission
		}
		return read(name)
	}
}

func TestRuntimeMountSystemdCredentialsRefusals(t *testing.T) {
	const path = "/run/credentials/" + credentialTestUnit
	const file = path + "/api-key"
	for _, tc := range []struct {
		name, want string
		mutate     func(*netnsAssertEnv)
	}{
		{"bare parent", "this unit's credentials must have", func(env *netnsAssertEnv) {
			read := env.readFile
			env.readFile = func(name string) ([]byte, error) {
				data, err := read(name)
				if name == "/proc/self/mountinfo" {
					data = []byte(strings.Split(string(data), "24 23")[0])
				}
				return data, err
			}
		}},
		{"sibling unit", "this unit's credentials must have", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, path, "/run/credentials/other.service") }},
		{"suffix evil", "this unit's credentials must have", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, path, path+"-evil") }},
		{"suffix dropin", "this unit's credentials must have", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, path, path+".d") }},
		{"unit name mismatch", "this unit's credentials must have", func(env *netnsAssertEnv) {
			read := env.readFile
			env.readFile = func(name string) ([]byte, error) {
				if name == "/proc/self/cgroup" {
					return []byte("0::/system.slice/other.service\n"), nil
				}
				return read(name)
			}
		}},
		{"hidden unit", "credentials require a visible", func(env *netnsAssertEnv) {
			read := env.readFile
			env.readFile = func(name string) ([]byte, error) {
				if name == "/proc/self/cgroup" {
					return []byte("0::/\n"), nil
				}
				return read(name)
			}
		}},
		{"legacy unit", "credentials require a visible", func(env *netnsAssertEnv) {
			read := env.readFile
			env.readFile = func(name string) ([]byte, error) {
				if name == "/proc/self/cgroup" {
					return []byte("1:name=systemd:/system.slice/" + credentialTestUnit + "\n"), nil
				}
				return read(name)
			}
		}},
		{"unreadable identity", "credentials require a visible", func(env *netnsAssertEnv) { credentialReadFailure(env, "/proc/self/cgroup") }},
		{"unreadable mountinfo", "read runtime mount evidence /proc/self/mountinfo", func(env *netnsAssertEnv) { credentialReadFailure(env, "/proc/self/mountinfo") }},
		{"unreadable host mountinfo", "read runtime mount evidence /proc/1/mountinfo", func(env *netnsAssertEnv) { credentialReadFailure(env, "/proc/1/mountinfo") }},
		{"missing parent mount", "credentials parent must", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "23 20 0:202 / /run/credentials ro,nosuid,nodev,noexec - tmpfs tmpfs rw\n", "")
		}},
		{"rw parent", "credentials parent must", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "/run/credentials ro", "/run/credentials rw")
		}},
		{"parent root", "credentials parent must", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "23 20 0:202 /", "23 20 0:202 /credentials")
		}},
		{"parent filesystem", "credentials parent must", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "- tmpfs tmpfs rw\n24", "- ramfs ramfs rw\n24")
		}},
		{"shared parent", "credentials parent must", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, "23 20 0:202", "23 20 0:50") }},
		{"rw credentials", "this unit's credentials must have", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, path+" ro", path+" rw") }},
		{"wrong filesystem", "this unit's credentials must have", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "24 23 0:203 / "+path+" ro,nosuid,nodev,noexec - tmpfs tmpfs rw", "24 23 0:203 / "+path+" ro,nosuid,nodev,noexec - ext4 /dev/disk rw")
		}},
		{"credential root", "this unit's credentials must have", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "24 23 0:203 /", "24 23 0:203 /elsewhere")
		}},
		{"same parent device", "this unit's credentials must have", func(env *netnsAssertEnv) { replaceCredentialMountEvidence(env, "24 23 0:203", "24 23 0:202") }},
		{"mount beneath", "unexpected mount in isolated runtime tree", func(env *netnsAssertEnv) {
			replaceCredentialMountEvidence(env, "24 23", "25 24 0:204 / "+file+" ro - tmpfs tmpfs rw\n24 23")
		}},
		{"wrong owner", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, path, os.ModeDir|0o550, 987) }},
		{"parent wrong owner", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, "/run/credentials", os.ModeDir|0o755, 987) }},
		{"symlinked path", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, path, os.ModeSymlink|0o777, 0) }},
		{"symlinked parent", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, "/run/credentials", os.ModeSymlink|0o777, 0) }},
		{"writable directory", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, path, os.ModeDir|0o570, 0) }},
		{"writable parent", "credentials directories must", func(env *netnsAssertEnv) { credentialStatOverride(env, "/run/credentials", os.ModeDir|0o777, 0) }},
		{"socket inside", "credentials must be root-owned regular files", func(env *netnsAssertEnv) { credentialStatOverride(env, file, os.ModeSocket|0o400, 0) }},
		{"symlink inside", "credentials must be root-owned regular files", func(env *netnsAssertEnv) { credentialStatOverride(env, file, os.ModeSymlink|0o400, 0) }},
		{"subdirectory inside", "credentials must be root-owned regular files", func(env *netnsAssertEnv) { credentialStatOverride(env, file, os.ModeDir|0o500, 0) }},
		{"credential wrong owner", "credentials must be root-owned regular files", func(env *netnsAssertEnv) { credentialStatOverride(env, file, 0o400, 987) }},
		{"credential writable by group", "credentials must be root-owned regular files", func(env *netnsAssertEnv) { credentialStatOverride(env, file, 0o460, 0) }},
		{"missing stat reader", "credential stat reader is unavailable", func(env *netnsAssertEnv) { env.lstat = nil }},
		{"unknown owner", "credentials directories must", func(env *netnsAssertEnv) {
			stat := env.lstat
			env.lstat = func(name string) (os.FileInfo, error) {
				if name == path {
					return fakeFileInfo{mode: os.ModeDir | 0o500}, nil
				}
				return stat(name)
			}
		}},
		{"unreadable directory stat", "inspect credentials directory /run/credentials/agent-worker.service", func(env *netnsAssertEnv) {
			stat := env.lstat
			env.lstat = func(name string) (os.FileInfo, error) {
				if name == path {
					return nil, os.ErrPermission
				}
				return stat(name)
			}
		}},
		{"unreadable credential stat", "inspect credential /run/credentials/agent-worker.service/api-key", func(env *netnsAssertEnv) {
			stat := env.lstat
			env.lstat = func(name string) (os.FileInfo, error) {
				if name == file {
					return nil, os.ErrPermission
				}
				return stat(name)
			}
		}},
		{"unreadable contents", "inspect credentials contents", func(env *netnsAssertEnv) {
			read := env.readDir
			env.readDir = func(name string) ([]os.DirEntry, error) {
				if name == path {
					return nil, os.ErrPermission
				}
				return read(name)
			}
		}},
		{"sibling directory entry", "must contain only agent-worker.service", func(env *netnsAssertEnv) {
			read := env.readDir
			env.readDir = func(name string) ([]os.DirEntry, error) {
				if name == "/run/credentials" {
					return fstest.MapFS{credentialTestUnit: &fstest.MapFile{Mode: os.ModeDir}, "other.service": &fstest.MapFile{Mode: os.ModeDir}}.ReadDir(".")
				}
				return read(name)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := credentialRuntimeFixture(credentialTestUnit, "tmpfs")
			tc.mutate(&env)
			if err := assertManagedRuntimeMounts(env); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("credential refusal = %v, want %q", err, tc.want)
			}
		})
	}
}
