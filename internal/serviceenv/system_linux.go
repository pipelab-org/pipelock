// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package serviceenv

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cliutil"
)

func defaultBackend() backend {
	return backend{command: systemCommand, readFile: readStableFile, readCandidate: readStableCandidate, identity: staticIdentity, execute: executeValidator}
}

// cleanHelperEnvironment follows containment's lifecycleManagerEnvironment.
// In particular, never inherit DBUS_SYSTEM_BUS_ADDRESS or SYSTEMD_HOST.
func cleanHelperEnvironment() []string {
	return []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "SYSTEMD_PAGER="}
}

type boundedOutput struct {
	buffer   bytes.Buffer
	overflow bool
	limit    int
}

func (b *boundedOutput) Len() int      { return b.buffer.Len() }
func (b *boundedOutput) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedOutput) Write(body []byte) (int, error) {
	n := len(body)
	limit := b.limit
	if limit == 0 {
		limit = maxObservationBytes
	}
	remaining := limit - b.Len()
	if len(body) > remaining {
		body = body[:remaining]
		b.overflow = true
	}
	_, _ = b.buffer.Write(body)
	return n, nil
}

func systemCommand(ctx context.Context, binary string, args ...string) ([]byte, int, error) {
	bounded, cancel := context.WithTimeout(ctx, commandBudget)
	defer cancel()
	var cmd *exec.Cmd
	switch binary {
	case "/usr/bin/systemctl":
		cmd = exec.CommandContext(bounded, "/usr/bin/systemctl")
	case "/usr/bin/busctl":
		cmd = exec.CommandContext(bounded, "/usr/bin/busctl")
	default:
		return nil, -1, errors.New("unsupported service observation helper")
	}
	cmd.Args = append(cmd.Args, args...)
	limit := maxObservationBytes
	if binary == "/usr/bin/busctl" && slices.Contains(args, "--xml-interface") {
		limit = maxCatalogBytes
	}
	return runObservationWithin(bounded, limit, cmd)
}

// runObservationWithin keeps the execution/resource contract independently
// testable without contacting a live system manager. systemCommand admits the
// helpers and supplies the bounded command context.
func runObservationWithin(ctx context.Context, limit int, cmd *exec.Cmd) ([]byte, int, error) {
	cmd.Env = cleanHelperEnvironment()
	cmd.WaitDelay = time.Second
	out := boundedOutput{limit: limit}
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	err := cmd.Run()
	if out.overflow {
		return nil, -1, errObservationOverflow
	}
	if ctx.Err() != nil {
		return nil, -1, errObservationPolicy
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
	return readStableFileWithin(path, maxObservationBytes)
}

// readStableCandidate reads the candidate configuration the way config.Load
// does: a symlinked path is followed and size is not capped (shipped presets
// are already within 4 KiB of the 64 KiB observation bound). The resolved leaf
// still gets the O_NOFOLLOW, regular-file and identity-stability checks.
func readStableCandidate(path string) (fileImage, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fileImage{}, errors.New("cannot open regular validation input")
	}
	return readStableFileWithin(resolved, -1)
}

// readStableFileWithin bounds the read to limit bytes; a negative limit is
// unbounded.
func readStableFileWithin(path string, limit int64) (fileImage, error) {
	var image fileImage
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if errors.Is(err, unix.ENOENT) {
		return image, errMissingFile
	}
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return image, errors.New("validation input leaf symlink is unsupported")
		}
		return image, errUnreadableFile
	}
	file := os.NewFile(uintptr(fd), path)
	defer func() { _ = file.Close() }()
	var before, after, named unix.Stat_t
	if unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || limit >= 0 && before.Size > limit {
		return image, errors.New("validation input is not a bounded regular file")
	}
	var reader io.Reader = file
	if limit >= 0 {
		reader = io.LimitReader(file, limit+1)
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return image, errUnreadableFile
	}
	if limit >= 0 && int64(len(body)) > limit {
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
		return id, fmt.Errorf("service user unavailable: %w", ErrUnavailable)
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
			return id, fmt.Errorf("service group unavailable: %w", ErrUnavailable)
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
		return id, fmt.Errorf("service supplementary groups unavailable: %w", ErrUnavailable)
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
			return id, fmt.Errorf("additional service group unavailable: %w", ErrUnavailable)
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
		return nil, fmt.Errorf("validation requires service identity privileges: %w", ErrUnavailable)
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
		return nil, fmt.Errorf("validation requires service supplementary groups: %w", ErrUnavailable)
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
	if opts.credential != nil {
		return (credentialValidation{opts: opts, env: env, id: id, candidate: candidate, binary: binary, before: before}).execute(ctx)
	}
	bounded, cancel := context.WithTimeout(ctx, cliutil.ServiceStartTimeout)
	defer cancel()
	// Linux /proc/self/fd and os/exec.ExtraFiles retain the opened executable
	// across the credential change. argv[0] remains the selected binary's name.
	cmd := exec.CommandContext(bounded, "/proc/self/fd/3", "check", "--config", "-")
	// Older validators remain usable for configs without the new token source.
	tokenFile, err := candidateTokenFile(candidate)
	if err != nil {
		return err
	}
	if tokenFile != "" {
		cmd.Args = append(cmd.Args, "--resolve-runtime-credentials")
	}
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
	if cmd.Start() != nil {
		return errValidatorStart
	}
	if cmd.Wait() != nil {
		return errors.New("selected validator failed")
	}
	if unix.Fstat(fd, &after) != nil || unix.Lstat(opts.Binary, &named) != nil || fileMetadata(&before) != fileMetadata(&after) || fileMetadata(&after) != fileMetadata(&named) {
		return errors.New("selected validator changed during execution")
	}
	return nil
}

// executeCredentialValidator asks PID 1 for a fresh credential, never borrowing
// /run/credentials/pipelock.service from an earlier invocation. systemd-run(1)
// --pipe carries the candidate through stdin; --setenv=NAME obtains values from
// the helper environment so token values never enter command-line arguments.
type credentialValidation struct {
	opts      CheckOptions
	env       []string
	id        identity
	candidate []byte
	binary    *os.File
	before    unix.Stat_t
}

func (v credentialValidation) execute(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return ErrUnavailable
	}
	return v.run(ctx, func(cmd *exec.Cmd) error { return cmd.Run() }, func(ctx context.Context, unit string) {
		_, _, _ = systemCommand(ctx, "/usr/bin/systemctl", "--system", "--no-ask-password", "stop", unit)
	})
}

func (v credentialValidation) run(ctx context.Context, run func(*exec.Cmd) error, stop func(context.Context, string)) error {
	args, err := credentialValidatorArgs(v.opts, v.env, v.id, v.binary.Fd())
	if err != nil {
		return err
	}

	bounded, cancel := context.WithTimeout(ctx, cliutil.ServiceStartTimeout)
	defer cancel()
	unit := "pipelock-config-check-" + strings.ToLower(rand.Text()) + ".service"
	args = append([]string{"--unit=" + unit}, args...)
	cmd := exec.CommandContext(bounded, "/usr/bin/systemd-run")
	cmd.Args = append(cmd.Args, args...)
	cmd.Env = append(cleanHelperEnvironment(), v.env...)
	cmd.Stdin = bytes.NewReader(v.candidate)
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	cmd.WaitDelay = time.Second
	// PID 1's runtime limit bounds the worker even if its client is killed. Also
	// stop this uniquely named, session-owned unit after any client outcome.
	err = run(cmd)
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), commandBudget)
	defer cleanupCancel()
	stop(cleanupCtx, unit)
	if err != nil {
		return errors.New("fresh systemd credential validator failed; output withheld")
	}
	var after, named unix.Stat_t
	if unix.Fstat(int(v.binary.Fd()), &after) != nil || unix.Lstat(v.opts.Binary, &named) != nil || fileMetadata(&v.before) != fileMetadata(&after) || fileMetadata(&after) != fileMetadata(&named) {
		return errors.New("selected validator changed during credential validation")
	}
	return nil
}

func credentialValidatorArgs(opts CheckOptions, env []string, id identity, fd uintptr) ([]string, error) {
	source := opts.credential
	if source == nil || source.Property != "LoadCredential" && source.Property != "LoadCredentialEncrypted" || !staticCredentialPath(opts.Binary) || !staticCredentialPath(filepath.Dir(opts.ConfigFile)) || !staticCredentialPath(source.Path) {
		return nil, errors.New("unsupported native credential validation paths")
	}
	groups := make([]string, len(id.Groups))
	for i, gid := range id.Groups {
		groups[i] = strconv.FormatUint(uint64(gid), 10)
	}
	// Bind the held executable inode before dropping identity. This keeps the
	// existing validator pinning contract when PID 1 creates the process.
	args := []string{
		"--system", "--no-ask-password", "--quiet", "--wait", "--pipe", "--collect", "--service-type=exec", "--expand-environment=no",
		"--property=User=" + strconv.FormatUint(uint64(id.UID), 10),
		"--property=Group=" + strconv.FormatUint(uint64(id.GID), 10),
		"--property=SupplementaryGroups=" + strings.Join(groups, " "),
		"--property=WorkingDirectory=" + filepath.Dir(opts.ConfigFile),
		"--property=BindReadOnlyPaths=/proc/" + strconv.Itoa(os.Getpid()) + "/fd/" + strconv.FormatUint(uint64(fd), 10) + ":" + opts.Binary,
		"--property=" + source.Property + "=" + source.Name + ":" + source.Path,
		"--property=RuntimeMaxSec=" + cliutil.ServiceStartTimeout.String(), "--property=TimeoutStartSec=" + cliutil.ServiceStartTimeout.String(), "--property=TimeoutStopSec=1s", "--property=LimitCORE=0",
	}
	// Remove absent inputs rather than setting them empty: LookupEnv consumers
	// distinguish those states. Keep observed values out of helper arguments.
	observed := make(map[string]string)
	for _, assignment := range env {
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || !validName(name) {
			return nil, errors.New("invalid validator environment")
		}
		observed[name] = value
	}
	var unset []string
	for _, name := range opts.credentialUnset {
		if !validName(name) || name == "CREDENTIALS_DIRECTORY" {
			return nil, errors.New("unsupported manager credential environment")
		}
		if _, ok := observed[name]; !ok {
			unset = append(unset, name)
		}
	}
	for _, name := range configurationEnvironmentKeys() {
		if _, ok := observed[name]; ok {
			args = append(args, "--setenv="+name)
		} else {
			unset = append(unset, name)
		}
	}
	slices.Sort(unset)
	unset = slices.Compact(unset)
	if len(unset) > 0 {
		args = append(args, "--property=UnsetEnvironment="+strings.Join(unset, " "))
	}
	args = append(args, "--", opts.Binary, "check", "--config", "-", "--resolve-runtime-credentials")
	if opts.RequireBuildCompatibility {
		args = append(args, "--require-build-compatibility")
	}
	return args, nil
}
