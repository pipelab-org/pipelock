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
	remove     func(string) error
	syncDir    func(string) error
	syncFile   func(string) error
}

func localWriterStorage() writerStorage {
	return writerStorage{
		createTemp: func(dir, pattern string) (writerFile, error) { return os.CreateTemp(dir, pattern) },
		link:       os.Link,
		remove:     os.Remove,
		syncDir:    syncWriterDir,
		syncFile:   syncWriterFile,
	}
}

func syncWriterDir(path string) error {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return err
	}
	return errors.Join(file.Sync(), file.Close())
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
