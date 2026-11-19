// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/directorysync"
)

const (
	writerTempPrefix = ".receipt-v3-tmp-"
	writerFileBytes  = 64 << 20
)

type writerFile interface {
	io.WriteCloser
	Name() string
	Sync() error
}

type writerStorage struct {
	createTemp func(string, string) (writerFile, error)
	link       func(string, string) error
	rename     func(string, string) error
	remove     func(string) error
	syncDir    func(string) error
	syncFile   func(string) error
}

func localWriterStorage() writerStorage {
	return writerStorage{
		createTemp: func(dir, pattern string) (writerFile, error) { return os.CreateTemp(dir, pattern) },
		link:       os.Link,
		rename:     os.Rename,
		remove:     os.Remove,
		syncDir:    directorysync.Sync,
		syncFile:   syncWriterFile,
	}
}

// A new directory needs the same publication barrier as a new stream file.
// A failed parent flush must prevent startup even if the name is visible.
func makeWriterDirectory(path string, syncDir func(string) error) error {
	parent := filepath.Dir(path)
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if !info.IsDir() {
			return errors.New("receipt evidence path is not a directory")
		}
	case !errors.Is(err, fs.ErrNotExist) || parent == path:
		return err
	default:
		if err := makeWriterDirectory(parent, syncDir); err != nil {
			return err
		}
		if err := os.Mkdir(path, 0o750); err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
	}
	// An existing name can be left by a failed parent flush. Confirm it
	// again before publishing into the directory on a retry.
	if parent != path {
		if err := syncDir(parent); err != nil {
			return fmt.Errorf("flush parent of receipt directory: %w", err)
		}
	}
	return nil
}

func syncWriterFile(path string) error {
	file, err := openEvidence(path)
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
}

func writeWriterLine(file writerFile, line []byte) error {
	n, err := file.Write(line)
	if err != nil {
		return fmt.Errorf("append receipt record: %w", err)
	}
	if n != len(line) {
		return fmt.Errorf("append receipt record: %w", io.ErrShortWrite)
	}
	return nil
}

// Publish never removes the final name. A failed directory sync can leave
// that name visible until a power loss, but it has not confirmed the record.
func (s writerStorage) publish(dir, name string, line []byte) (writerFile, bool, error) {
	file, err := s.createTemp(dir, writerTempPrefix)
	if err != nil {
		return nil, false, fmt.Errorf("create receipt file: %w", err)
	}
	defer func() { _ = s.remove(file.Name()) }()
	if err := writeWriterLine(file, line); err != nil {
		return nil, false, errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return nil, false, errors.Join(fmt.Errorf("flush new receipt file: %w", err), file.Close())
	}
	if err := s.link(file.Name(), filepath.Join(dir, name)); err != nil {
		return nil, false, errors.Join(fmt.Errorf("publish receipt file: %w", err), file.Close())
	}
	if err := s.syncDir(dir); err != nil {
		return nil, true, errors.Join(fmt.Errorf("flush receipt directory after publication: %w", err), file.Close())
	}
	return file, true, nil
}

func (s writerStorage) cleanup(dir string, entries []os.DirEntry) error {
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), writerTempPrefix) {
			continue
		}
		if err := s.remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("remove temporary receipt file: %w", err)
		}
	}
	return nil
}

func writerFilename(stream string, seq int64) string {
	return fmt.Sprintf("%s-%0*d%s", stream, layoutStartDigits, seq, layoutFileSuffix)
}

// syncFaultFile fails one flush, then delegates. The pointer stays in the
// writer so the one-shot error is consumed once.
type syncFaultFile struct {
	writerFile
	err error
}

func (f *syncFaultFile) Sync() error {
	if f.err != nil {
		err := f.err
		f.err = nil
		return err
	}
	return f.writerFile.Sync()
}

// ArmNextSyncFailure makes the next flush of the open stream file fail once.
func (w *StreamWriter) ArmNextSyncFailure(err error) {
	if w == nil || w.active.file == nil || err == nil {
		return
	}
	w.active.file = &syncFaultFile{writerFile: w.active.file, err: err}
}
