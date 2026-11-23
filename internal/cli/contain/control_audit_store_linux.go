// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package contain

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/cli/contain/workspacediff"
)

type controlAuditStore struct {
	path string
	uid  uint32
	gid  uint32
}

func controlBaselineFilename(root string) string {
	return fmt.Sprintf("%x.json", sha256.Sum256([]byte(root)))
}

// Like openLifecycleDirectory, walk directory handles with O_NOFOLLOW.
// The two private directories must also have the store's exact mode and owner.
func (s controlAuditStore) open(create bool) (*os.File, error) {
	if !filepath.IsAbs(s.path) || filepath.Clean(s.path) != s.path {
		return nil, errors.New("workspace control baseline store path must be clean and absolute")
	}
	parts := strings.Split(strings.TrimPrefix(s.path, "/"), "/")
	if len(parts) < 2 {
		return nil, errors.New("workspace control baseline store needs a private parent")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
	}()
	for i, part := range parts {
		private := i >= len(parts)-2
		if create && private {
			err := unix.Mkdirat(fd, part, 0o700)
			if err == nil {
				if err := unix.Fsync(fd); err != nil {
					return nil, err
				}
			} else if !errors.Is(err, unix.EEXIST) {
				return nil, err
			}
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		_ = unix.Close(fd)
		fd = next
		if err := s.verifyDir(fd, private); err != nil {
			return nil, fmt.Errorf("baseline directory component %q: %w", part, err)
		}
	}
	file := os.NewFile(uintptr(fd), s.path)
	fd = -1
	return file, nil
}

func (s controlAuditStore) verifyDir(fd int, private bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	return s.checkDir(st, private)
}

func (s controlAuditStore) checkDir(st unix.Stat_t, private bool) error {
	if private {
		if st.Uid != s.uid || st.Gid != s.gid || st.Mode&0o7777 != 0o700 {
			return errors.New("private directory must be root-owned with mode 0700")
		}
	} else if (st.Uid != 0 && st.Uid != s.uid) || (st.Mode&0o022 != 0 && (st.Uid != 0 || st.Mode&unix.S_ISVTX == 0)) {
		return errors.New("unsafe ancestor directory owner or mode")
	}
	return nil
}

func (s controlAuditStore) load(dir *os.File, root string) (workspacediff.ControlSurfaceSnapshot, error) {
	name := controlBaselineFilename(root)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return workspacediff.ControlSurfaceSnapshot{}, err
	}
	f := os.NewFile(uintptr(fd), name)
	defer func() { _ = f.Close() }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return workspacediff.ControlSurfaceSnapshot{}, err
	}
	if err := s.checkFile(st); err != nil {
		return workspacediff.ControlSurfaceSnapshot{}, err
	}
	return workspacediff.DecodeControlBaseline(f, root)
}

func (s controlAuditStore) checkFile(st unix.Stat_t) error {
	if st.Uid != s.uid || st.Gid != s.gid || st.Mode != unix.S_IFREG|0o600 || st.Nlink != 1 {
		return errors.New("workspace control baseline must be a root-owned regular file with mode 0600 and one link")
	}
	return nil
}

func writeControlBaseline(dir *os.File, root string, snapshot workspacediff.ControlSurfaceSnapshot, replace bool) error {
	body, err := workspacediff.EncodeControlBaseline(snapshot)
	if err != nil {
		return err
	}
	dirFD := int(dir.Fd())
	next := ".next-" + rand.Text()
	fd, err := unix.Openat(dirFD, next, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Unlinkat(dirFD, next, 0) }()
	f := os.NewFile(uintptr(fd), next)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	_, writeErr := f.Write(body)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return err
	}
	name := controlBaselineFilename(root)
	if replace {
		err = unix.Renameat(dirFD, next, dirFD, name)
	} else {
		err = unix.Renameat2(dirFD, next, dirFD, name, unix.RENAME_NOREPLACE)
	}
	if err != nil {
		return err
	}
	return dir.Sync()
}
