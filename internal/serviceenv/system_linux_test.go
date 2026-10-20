// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceenv

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "observe-") {
		switch os.Args[1] {
		case "observe-success":
			_, _ = fmt.Fprint(os.Stdout, "observed")
			os.Exit(0)
		case "observe-failure":
			_, _ = fmt.Fprint(os.Stderr, "secret-sentinel")
			os.Exit(7)
		case "observe-overflow":
			_, _ = fmt.Fprint(os.Stdout, strings.Repeat("x", maxObservationBytes+1))
			os.Exit(0)
		}
		os.Exit(33)
	}
	if len(os.Args) > 1 && os.Args[1] == "check" {
		// Exercise the real config loader behind the descriptor execution seam.
		// The companion license file must resolve against the candidate's dir.
		if os.Getenv("CALLER_ONLY") != "" || os.Getenv("LD_PRELOAD") != "" || os.Getenv("GODEBUG") != "" {
			os.Exit(31)
		}
		if _, err := config.Load("-"); err != nil {
			_, _ = fmt.Fprintln(os.Stdout, "secret-sentinel", err)
			_, _ = fmt.Fprintln(os.Stderr, "secret-sentinel", err)
			os.Exit(32)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func currentIdentity(t *testing.T) identity {
	t.Helper()
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	id := identity{UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())} // #nosec G115 -- kernel uid/gid values.
	for _, g := range groups {
		id.Groups = append(id.Groups, uint32(g))
	} // #nosec G115 -- kernel gid values.
	slices.Sort(id.Groups)
	id.Groups = slices.Compact(id.Groups)
	return id
}

func TestExecuteValidatorIsolatedAndRelativeCompanion(t *testing.T) {
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "license.txt"), []byte("test-license"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CALLER_ONLY", "caller-secret")
	t.Setenv(config.EnvLicenseKey, "caller-license")
	opts := CheckOptions{Binary: binary, ConfigFile: filepath.Join(dir, "candidate.yaml"), RequireBuildCompatibility: true}
	id := currentIdentity(t)
	if err := executeValidator(t.Context(), opts, []string{"HOME=" + dir}, id, []byte("mode: balanced\nlicense_file: license.txt\n")); err != nil {
		t.Fatal(err)
	}
	if err := executeValidator(t.Context(), opts, nil, id, []byte("license_file: missing.txt\n")); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("child rejection was not safely reported")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if executeValidator(ctx, opts, nil, id, []byte("mode: balanced\n")) == nil {
		t.Fatal("cancelled validator accepted")
	}
}

func TestExecuteValidatorRejectsUnsafeBinary(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("not executable"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{regular, link, dir, filepath.Join(dir, "missing")} {
		if executeValidator(t.Context(), CheckOptions{Binary: path, ConfigFile: filepath.Join(dir, "config.yaml")}, nil, currentIdentity(t), nil) == nil {
			t.Fatal("unsafe validator accepted")
		}
	}
}

func TestReadStableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input")
	if err := os.WriteFile(path, []byte("A=value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := readStableFile(path)
	if err != nil || string(first.Data) != "A=value\n" || first.Stamp == "" {
		t.Fatal("regular file not observed")
	}
	second, err := readStableFile(path)
	if err != nil || first.Stamp != second.Stamp {
		t.Fatal("stable stamp changed")
	}
	if err := os.WriteFile(path, []byte("A=other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := readStableFile(path)
	if err != nil || third.Stamp == first.Stamp {
		t.Fatal("changed bytes not detected")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{link, fifo, dir} {
		if _, err := readStableFile(name); err == nil {
			t.Fatal("nonregular input accepted")
		}
	}
	if _, err := readStableFile(filepath.Join(dir, "missing")); !errors.Is(err, errMissingFile) {
		t.Fatal("missing input not distinguished")
	}
	if err := os.WriteFile(path, make([]byte, maxObservationBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableFile(path); err == nil {
		t.Fatal("oversize input accepted")
	}
}

// config.Load follows a symlinked path and has no size cap, and shipped presets
// sit within 4 KiB of the 64 KiB observation bound, so the candidate reader must
// accept both while still refusing non-regular files.
func TestReadStableCandidateMatchesLoaderInputs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pipelock.yaml")
	body := make([]byte, 2*maxObservationBytes)
	for i := range body {
		body[i] = '#'
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{path, link} {
		image, err := readStableCandidate(name)
		if err != nil || len(image.Data) != len(body) {
			t.Fatalf("candidate %s not read: %v", filepath.Base(name), err)
		}
	}
	if _, err := readStableFile(path); err == nil {
		t.Fatal("environment-file reader lost its bound")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{fifo, dir, filepath.Join(dir, "missing")} {
		if _, err := readStableCandidate(name); err == nil {
			t.Fatal("nonregular candidate accepted")
		}
	}
}

func TestStaticIdentity(t *testing.T) {
	u, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	id, err := staticIdentity(u.Uid, u.Gid, []string{u.Gid})
	if err != nil {
		t.Fatal(err)
	}
	if strconv.FormatUint(uint64(id.UID), 10) != u.Uid || !slices.Contains(id.Groups, id.GID) || !filepath.IsAbs(id.Home) {
		t.Fatal("static identity mismatch")
	}
	if _, err := staticIdentity(u.Uid, strconv.FormatUint(uint64(id.GID)+1, 10), nil); err == nil {
		t.Fatal("replacement primary group accepted")
	}
	if _, err := staticIdentity("pipelock-test-account-that-does-not-exist", "", nil); err == nil {
		t.Fatal("missing user accepted")
	}
	if _, err := staticIdentity(u.Uid, "", []string{"pipelock-test-group-that-does-not-exist"}); err == nil {
		t.Fatal("missing group accepted")
	}
	if _, err := validatorCredential(currentIdentity(t)); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		bad := currentIdentity(t)
		bad.UID++
		if _, err := validatorCredential(bad); err == nil {
			t.Fatal("identity mismatch accepted")
		}
		bad = currentIdentity(t)
		bad.Groups = append(bad.Groups, 4294967294)
		if _, err := validatorCredential(bad); err == nil {
			t.Fatal("group mismatch accepted")
		}
	}
}

func TestBoundedOutputAndHelperPolicy(t *testing.T) {
	var out boundedOutput
	if n, err := out.Write(make([]byte, maxObservationBytes+1)); err != nil || n != maxObservationBytes+1 || !out.overflow || out.Len() != maxObservationBytes {
		t.Fatal("output not bounded")
	}
	if _, _, err := systemCommand(t.Context(), "/untrusted/helper"); err == nil {
		t.Fatal("arbitrary helper accepted")
	}
	for _, env := range cleanHelperEnvironment() {
		if strings.HasPrefix(env, "DBUS_SYSTEM_BUS_ADDRESS=") || strings.HasPrefix(env, "SYSTEMD_HOST=") {
			t.Fatal("remote-manager environment included")
		}
	}
}

func runTestObservation(ctx context.Context, limit int, args ...string) ([]byte, int, error) {
	bounded, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	cmd := exec.CommandContext(bounded, "/proc/self/exe")
	cmd.Args = append(cmd.Args, args...)
	return runObservationWithin(bounded, limit, cmd)
}

func TestObservationExecutionPolicy(t *testing.T) {
	body, code, err := runTestObservation(t.Context(), maxObservationBytes, "observe-success")
	if err != nil || code != 0 || string(body) != "observed" {
		t.Fatal("successful observation not retained")
	}
	body, code, err = runTestObservation(t.Context(), maxObservationBytes, "observe-failure")
	if err != nil || code != 7 || len(body) != 0 {
		t.Fatal("helper failure output escaped")
	}
	if _, _, err := runTestObservation(t.Context(), maxObservationBytes, "observe-overflow"); err == nil {
		t.Fatal("oversized observation accepted")
	}
	if _, _, err := runObservationWithin(t.Context(), maxObservationBytes, exec.CommandContext(t.Context(), "/proc/self/exe/missing")); err == nil || strings.Contains(err.Error(), "secret-sentinel") {
		t.Fatal("missing observation helper accepted")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, _, err := systemCommand(ctx, "/usr/bin/systemctl"); err == nil {
		t.Fatal("cancelled observation accepted")
	}
	// Exercise the public wiring without reading the actual manager.
	if Check(t.Context(), CheckOptions{Service: "unrelated"}) == nil {
		t.Fatal("public checker accepted unrelated unit")
	}
}

func TestCatalogOutputLimitAndRealOverflow(t *testing.T) {
	// The same helper output crosses the property limit but fits a D-Bus message.
	body, code, err := runTestObservation(t.Context(), maxCatalogBytes, "observe-overflow")
	if err != nil || code != 0 || len(body) != maxObservationBytes+1 {
		t.Fatalf("catalog-sized helper output refused: %v", err)
	}
	// A smaller injected cap exercises genuine subprocess overflow without
	// allocating a 128 MiB fixture just to cross the production bound.
	if _, _, err := runTestObservation(t.Context(), 4, "observe-success"); err == nil {
		t.Fatal("subprocess overflow accepted")
	}
}

func TestStableFileAccessFailureClassification(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readStableFile(filepath.Join(parent, "child")); !errors.Is(err, errUnreadableFile) {
		t.Fatal("OS open failure lost optional-file classification")
	}
}
