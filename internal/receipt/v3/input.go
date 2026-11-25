// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"bytes"
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	contract "github.com/luckyPipewrench/pipelock/internal/contract/receipt"
)

type Head struct {
	Stream string
	Position
}

type Sequence struct {
	Stream string
	Seq    int64
}

// LegacyEnd is an independent endpoint expectation for a single legacy chain.
type LegacyEnd struct {
	Head     string
	Sequence *uint64
}

// LegacySelection binds legacy verifier controls in a mixed directory. All
// presented chains still contribute to cutover membership verification.
type LegacySelection struct {
	Session  string
	Group    string
	Bindings *contract.ChainVerifyOptions
}

// Options contains caller-supplied evidence requirements.
type Options struct {
	Keys                  []ed25519.PublicKey
	ExpectHeads           []Head
	ExpectSequences       []Sequence
	LegacyEnd             *LegacyEnd
	LegacySelection       LegacySelection
	GenericLegacyLabels   bool
	ExpectLineage         string
	AcceptDiscontinuities []string
	AllowPartialHistories []string
	AllowPrefix           bool
	AllowUnpinned         bool
	Directory             bool
	ExplicitV3            bool
	DiskIndex             bool
}

func (opts Options) validate() error {
	legacy := opts.LegacySelection
	if !opts.Directory && (legacy.Session != "" || legacy.Group != "" || legacy.Bindings != nil) {
		return errors.New("legacy options require mixed directory scope")
	}
	if legacy.Group != "" && (legacy.Session != "" || len(opts.Keys) == 0 || opts.AllowUnpinned ||
		legacy.Bindings != nil || opts.LegacyEnd != nil) {
		return errors.New("--group requires pinned keys and no other legacy selection")
	}
	if opts.LegacyEnd != nil && (!opts.Directory || opts.LegacyEnd.Head == "" && opts.LegacyEnd.Sequence == nil) {
		return errors.New("legacy endpoint expectations require mixed directory scope and an expected head or sequence")
	}
	if opts.ExplicitV3 && opts.Directory {
		return errors.New("explicit v3 format applies only to a single file")
	}
	if opts.ExpectLineage != "" && !isLowerHex(opts.ExpectLineage, 32) {
		return errors.New("expected lineage must be 32 lowercase hexadecimal characters")
	}
	for _, id := range opts.AllowPartialHistories {
		if !isLowerHex(id, 32) {
			return errors.New("partial history must name a 32-character stream ID")
		}
	}
	for _, id := range opts.AcceptDiscontinuities {
		if !isDigest(id) {
			return errors.New("accepted discontinuity must be a record ID")
		}
	}
	return nil
}

type inputFile struct {
	path   string
	stream string
	start  int64
	code   string
}

var streamName = regexp.MustCompile(`^([0-9a-f]{32})-([0-9]{16})\.receipt-v3\.jsonl$`)

// ParseHead parses the v3 command-line form stream:seq:sha256:digest.
func ParseHead(value string) (Head, error) {
	stream, rest, ok := strings.Cut(value, ":")
	seq, record, separated := strings.Cut(rest, ":")
	sequence, err := ParseSequence(stream + ":" + seq)
	if !ok || !separated || err != nil || !isDigest(record) {
		return Head{}, errors.New("expected head must be stream:seq:sha256:digest")
	}
	return Head{sequence.Stream, Position{record, sequence.Seq}}, nil
}

// ParseSequence parses the v3 command-line form stream:seq.
func ParseSequence(value string) (Sequence, error) {
	stream, seq, ok := strings.Cut(value, ":")
	number, err := strconv.ParseInt(seq, 10, 64)
	if !ok || !isLowerHex(stream, 32) || err != nil || number < 0 || number > maxInteger ||
		strconv.FormatInt(number, 10) != seq {
		return Sequence{}, errors.New("expected sequence must be stream:seq")
	}
	return Sequence{stream, number}, nil
}

// DecodeKeys converts the validated hex public keys accepted by the legacy
// commands into public keys for the v3 verifier.
func DecodeKeys(keys []string) ([]ed25519.PublicKey, error) {
	out := make([]ed25519.PublicKey, 0, len(keys))
	for _, key := range keys {
		decoded, err := hex.DecodeString(key)
		if err != nil {
			return nil, fmt.Errorf("decode public key: %w", err)
		}
		if len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("wrong Ed25519 public key length")
		}
		out = append(out, decoded)
	}
	return out, nil
}

func identify(path string) (inputFile, bool) {
	file := inputFile{path: path, start: -1}
	name := filepath.Base(path)
	version := contract.ProfileFilenameVersion(name)
	if version == "" {
		return file, false
	}
	if version != "3" {
		file.code = codeUnknownProfile
		return file, true
	}
	fields := streamName.FindStringSubmatch(name)
	if fields == nil {
		file.code = codeFileLayout
		return file, true
	}
	file.stream = fields[1]
	file.start, _ = strconv.ParseInt(fields[2], 10, 64)
	return file, true
}

// ClaimsInput identifies a v3 or later receipt claim before legacy dispatch.
func ClaimsInput(path string, directory bool) (bool, error) {
	if directory {
		dir, entries, err := readInputDirectory(path)
		if err != nil {
			return false, err
		}
		var probeErr error
		for _, entry := range entries {
			if _, known := identify(entry.Name()); known {
				return true, nil
			}
			if !entry.IsDir() && legacyCandidate(entry.Name()) && entry.Type().IsRegular() {
				claimed, err := startsWithProfile(filepath.Join(dir, entry.Name()))
				if claimed {
					return true, nil
				}
				if probeErr == nil {
					probeErr = err
				}
			}
		}
		return false, probeErr
	}
	if _, known := identify(path); known {
		return true, nil
	}
	return startsWithProfile(path)
}

// ClaimsContent identifies the receipt profile prefix on a byte-oriented input
// that has no filename, such as a fleet audit payload.
func ClaimsContent(data []byte) bool {
	return bytes.HasPrefix(data, []byte(contract.ProfileEnvelopePrefix))
}

func startsWithProfile(path string) (bool, error) {
	f, err := openEvidence(path)
	if err != nil {
		return false, fmt.Errorf("open evidence file: %w", err)
	}
	defer func() { _ = f.Close() }()
	claimed, err := contract.HasProfileEnvelope(f)
	if err != nil {
		return false, fmt.Errorf("read evidence prefix: %w", err)
	}
	return claimed, nil
}

func readInputDirectory(path string) (string, []os.DirEntry, error) {
	dir, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", nil, fmt.Errorf("resolve evidence directory: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", nil, fmt.Errorf("read evidence directory: %w", err)
	}
	return dir, entries, nil
}

func discover(paths []string, opts Options, skip string) (files []inputFile, legacy []string, inventory map[string][]string, ignored int, err error) {
	inventory = make(map[string][]string)
	if opts.Directory {
		if len(paths) != 1 || opts.ExplicitV3 {
			return nil, nil, nil, 0, errors.New("directory scope requires exactly one directory")
		}
		dir, entries, err := readInputDirectory(paths[0])
		if err != nil {
			return nil, nil, nil, 0, err
		}
		paths = nil
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			_, v3 := identify(path)
			_, isInventory := inventoryID(entry.Name())
			if v3 || isInventory || legacyCandidate(entry.Name()) {
				if !entry.Type().IsRegular() {
					return nil, nil, nil, 0, fmt.Errorf("evidence path is not a regular file: %s", path)
				}
				paths = append(paths, path)
			} else {
				ignored++
			}
		}
	}
	ordered := slices.Clone(paths)
	slices.Sort(ordered)
	for _, path := range slices.Compact(ordered) {
		base := filepath.Base(path)
		if id, ok := inventoryID(base); ok && !opts.ExplicitV3 {
			inventory[id] = append(inventory[id], path)
			continue
		}
		file, identified := identify(path)
		if opts.ExplicitV3 && !identified {
			identified = true
		}
		if identified {
			if skip == codeUnknownProfile && file.code == codeUnknownProfile {
				file.code = ""
			}
			files = append(files, file)
			continue
		}
		claimed, checkErr := startsWithProfile(path)
		if checkErr != nil {
			return nil, nil, nil, 0, checkErr
		}
		if claimed && skip != codeV3ContentUnclaimed {
			file.code = codeV3ContentUnclaimed
			files = append(files, file)
			continue
		}
		legacy = append(legacy, path)
	}
	return files, legacy, inventory, ignored, nil
}

func readBounded(ctx context.Context, r *bufio.Reader) (line []byte, complete bool, err error) {
	// ReadSlice returns at most the configured buffer size. Drain an overlong
	// line without allocating its attacker-controlled length.
	line, err = r.ReadSlice('\n')
	switch {
	case err == nil:
		return line, true, nil
	case errors.Is(err, io.EOF):
		return line, false, nil
	case !errors.Is(err, bufio.ErrBufferFull):
		return nil, false, err
	}
	for errors.Is(err, bufio.ErrBufferFull) {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		_, err = r.ReadSlice('\n')
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, err
	}
	// The caller needs only a nonempty indication for an unterminated tail.
	return line, err == nil, nil
}

type stagedRecord struct {
	Common
	id          string
	unknown     bool
	bodyCode    string
	afterDamage bool
}

func (r stagedRecord) position() *Position {
	return &Position{r.id, r.Seq}
}

func (r stagedRecord) finding(code string) Finding {
	return Finding{Class: findingClasses[code], Code: code, Stream: r.Stream, Seq: &r.Seq, Record: r.id}
}

// recordWriter stages the parsed record and its original canonical payload.
type recordWriter func(context.Context, stagedRecord, []byte) error
