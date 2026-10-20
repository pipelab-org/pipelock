// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceenv

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func defaultBackend() backend {
	return backend{command: systemCommand, readFile: readStableFile, identity: staticIdentity, execute: executeValidator}
}

// cleanHelperEnvironment follows containment's lifecycleManagerEnvironment.
// In particular, never inherit DBUS_SYSTEM_BUS_ADDRESS or SYSTEMD_HOST.
func cleanHelperEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER="}
}

type boundedOutput struct {
	buffer   bytes.Buffer
	overflow bool
}

func (b *boundedOutput) Len() int      { return b.buffer.Len() }
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedOutput) Write(body []byte) (int, error) {
	n := len(body)
	remaining := maxObservationBytes - b.Len()
	if len(body) > remaining {
		body = body[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(body)
	return n, nil
}

func systemCommand(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
	if binary != "/usr/bin/systemctl" && binary != "/usr/bin/busctl" {
		return nil, -1, errors.New("unsupported service observation helper")
	}
	return runObservation(ctx, binary, args...)
}

// runObservation keeps the execution/resource contract independently testable
// without contacting a live system manager. systemCommand admits the helpers.
func runObservation(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
	bounded, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	cmd := exec.CommandContext(bounded, binary, args...) //nolint:gosec // Fixed absolute helpers; no shell.
	cmd.Env = cleanHelperEnvironment()
	cmd.WaitDelay = time.Second
	var out boundedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if out.overflow || bounded.Err() != nil {
		return nil, -1, errors.New("service observation exceeded its resource policy")
	}
	var exited *exec.ExitError
	if errors.As(err, &exited) {
		return out.Bytes(), exited.ExitCode(), nil
	}
	if err != nil {
		return nil, -1, errors.New("cannot start service observation helper")
	}
	return out.Bytes(), 0, nil
}

func fileMetadata(st *unix.Stat_t) string {
	return fmt.Sprintf("%d:%d:%d:%d:%d:%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Size, st.Mode, st.Uid, st.Gid, st.Mtim.Sec, st.Mtim.Nsec, st.Ctim.Sec, st.Ctim.Nsec)
}

// O_NONBLOCK prevents a raced FIFO from hanging before fstat rejects it.
// O_NOFOLLOW rejects a substituted leaf symlink. The held inode and the name
// must still agree after the bounded read.
func readStableFile(path string) (fileImage, error) {
	var image fileImage
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return image, errMissingFile
	}
	if err != nil {
		return image, errors.New("cannot open regular validation input")
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Size > maxObservationBytes {
		return image, errors.New("validation input is not a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxObservationBytes+1))
	if err != nil || len(body) > maxObservationBytes {
		return image, errors.New("cannot read bounded validation input")
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(path, &named) != nil || fileMetadata(&before) != fileMetadata(&after) || fileMetadata(&after) != fileMetadata(&named) {
		return image, errors.New("validation input changed while reading")
	}
	return fileImage{Data: body, Stamp: contentStamp(body, fileMetadata(&after))}, nil
}

func numericID(text string) (uint32, error) {
	value, err := strconv.ParseUint(text, 10, 32)
	return uint32(value), err
}

func lookupStaticUser(name string) (*user.User, error) {
	if name == "" {
		name = "root"
	}
	if _, err := numericID(name); err == nil {
		return user.LookupId(name)
	}
	return user.Lookup(name)
}

func lookupStaticGroup(name string) (uint32, error) {
	if id, err := numericID(name); err == nil {
		return id, nil
	}
	group, err := user.LookupGroup(name)
	if err != nil {
		return 0, err
	}
	return numericID(group.Gid)
}

func staticIdentity(name, group string, additional []string) (identity, error) {
	var id identity
	u, err := lookupStaticUser(name)
	if err != nil {
		return id, errors.New("service user unavailable")
	}
	id.UID, err = numericID(u.Uid)
	if err != nil {
		return id, errors.New("invalid service uid")
	}
	id.GID, err = numericID(u.Gid)
	if err != nil {
		return id, errors.New("invalid service gid")
	}
	if group != "" {
		configured, lookupErr := lookupStaticGroup(group)
		if lookupErr != nil {
			return id, errors.New("service group unavailable")
		}
		// os/user.GroupIds uses the account's primary gid. It cannot express
		// getgrouplist with a replacement primary gid, so do not guess the
		// resulting membership when Group= changes that gid.
		if configured != id.GID {
			return id, errors.New("service primary-group override is unsupported")
		}
	}
	// systemd.exec(5): SupplementaryGroups extends the user's group database
	// membership, including when Group= overrides the primary group.
	groups, err := u.GroupIds()
	if err != nil {
		return id, errors.New("service supplementary groups unavailable")
	}
	for _, text := range groups {
		gid, err := numericID(text)
		if err != nil {
			return id, errors.New("invalid supplementary gid")
		}
		id.Groups = append(id.Groups, gid)
	}
	for _, text := range additional {
		gid, err := lookupStaticGroup(text)
		if err != nil {
			return id, errors.New("additional service group unavailable")
		}
		id.Groups = append(id.Groups, gid)
	}
	slices.Sort(id.Groups)
	id.Groups = slices.Compact(id.Groups)
	id.Home = u.HomeDir
	if !filepath.IsAbs(id.Home) {
		return id, errors.New("service home is not absolute")
	}
	return id, nil
}

func validatorCredential(id identity) (*syscall.Credential, error) {
	if os.Geteuid() == 0 {
		return &syscall.Credential{Uid: id.UID, Gid: id.GID, Groups: id.Groups}, nil
	}
	groups, err := os.Getgroups()
	if err != nil || int64(os.Geteuid()) != int64(id.UID) || int64(os.Getegid()) != int64(id.GID) {
		return nil, errors.New("validation requires service identity privileges")
	}
	actual := make([]uint32, 0, len(groups))
	for _, group := range groups {
		if group < 0 {
			return nil, errors.New("invalid process group")
		}
		actual = append(actual, uint32(group)) // #nosec G115 -- kernel group IDs are uint32.
	}
	slices.Sort(actual)
	actual = slices.Compact(actual)
	if !slices.Equal(actual, id.Groups) {
		return nil, errors.New("validation requires service supplementary groups")
	}
	return nil, nil
}

func executeValidator(ctx context.Context, opts CheckOptions, env []string, id identity, candidate []byte) error {
	credential, err := validatorCredential(id)
	if err != nil {
		return err
	}
	fd, err := unix.Open(opts.Binary, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return errors.New("cannot open selected validator")
	}
	binary := os.NewFile(uintptr(fd), opts.Binary)
	defer func() { _ = binary.Close() }()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0o111 == 0 {
		return errors.New("selected validator is not a regular executable")
	}
	bounded, cancel := context.WithTimeout(ctx, cliutil.ServiceStartTimeout)
	defer cancel()
	// Linux /proc/self/fd and os/exec.ExtraFiles retain the opened executable
	// across the credential change. argv[0] remains the selected binary's name.
	cmd := exec.CommandContext(bounded, "/proc/self/fd/3", "check", "--config", "-")
	cmd.Args[0] = opts.Binary
	if opts.RequireBuildCompatibility {
		cmd.Args = append(cmd.Args, "--require-build-compatibility")
	}
	cmd.ExtraFiles = []*os.File{binary}
	cmd.Env = append([]string{}, env...)
	cmd.Dir = filepath.Dir(opts.ConfigFile)
	cmd.Stdin = bytes.NewReader(candidate)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: credential}
	if cmd.Run() != nil {
		return errors.New("selected validator failed")
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(opts.Binary, &named) != nil || fileMetadata(&before) != fileMetadata(&after) || fileMetadata(&after) != fileMetadata(&named) {
		return errors.New("selected validator changed during execution")
	}
	return nil
}
