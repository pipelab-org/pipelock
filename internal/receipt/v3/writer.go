// Copyright 2026 Pipelab
// SPDX-License-Identifier: Apache-2.0

package v3

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	endedClosed     = "closed"
	endedUnsealed   = "unsealed"
	endedWriteError = "write_error"
	closeRollover   = "rollover"
	closeShutdown   = "shutdown"
)

// StreamWriterOptions captures the settings that describe a stream for its
// whole lifetime. Prior keys are used only for startup verification.
type StreamWriterOptions struct {
	Dir              string
	SigningKey       ed25519.PrivateKey
	PriorSignerKeys  []ed25519.PublicKey
	Coverage         Coverage
	Identity         Writer
	PolicyHash       string
	Posture          *Posture
	RecorderSession  string
	Heartbeat        time.Duration
	OnHeartbeatError func(error)
	Detector         receiptcontent.Detector
	Clock            func() time.Time
	Random           io.Reader
}

type writerStream struct {
	id        string
	confirmed Position
	file      writerFile
	bytes     int
	beat      int64
}

// StreamWriter owns the evidence directory for its lifetime. It serializes
// appends, including their flushes, and never reuses a failed stream.
type StreamWriter struct {
	dir           string
	key           ed25519.PrivateKey
	lock          *recorder.EvidenceCeremonyLock
	storage       writerStorage
	gate          chan struct{}
	detector      receiptcontent.Detector
	open          StreamOpen
	signer        string
	now           func() time.Time
	random        io.Reader
	fileBytes     int
	stopHeartbeat func()

	active     writerStream
	previous   *Previous
	fatal      error
	closed     bool
	closeErr   error
	durability Durability
	repairs    []Action
}

// OpenStreamWriter verifies and re-flushes any predecessor before publishing
// a new stream. A second writer cannot inspect or mutate the directory.
func OpenStreamWriter(ctx context.Context, opts StreamWriterOptions) (*StreamWriter, error) {
	return openStreamWriter(ctx, opts, localWriterStorage())
}

func openStreamWriter(ctx context.Context, opts StreamWriterOptions, storage writerStorage) (_ *StreamWriter, err error) {
	if opts.Dir == "" {
		return nil, errors.New("receipt evidence directory is required")
	}
	if len(opts.SigningKey) != ed25519.PrivateKeySize {
		return nil, errors.New("receipt signing key is not an Ed25519 private key")
	}
	key := ed25519.NewKeyFromSeed(opts.SigningKey.Seed())
	if !key.Equal(opts.SigningKey) {
		return nil, errors.New("receipt signing key does not match its public key")
	}
	if opts.Coverage.ContentScan && opts.Detector == nil {
		return nil, errors.New("receipt content scanning requires a detector")
	}
	dir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolve receipt evidence directory: %w", err)
	}
	if err := makeWriterDirectory(dir, storage.syncDir); err != nil {
		return nil, fmt.Errorf("create receipt evidence directory: %w", err)
	}
	lock, err := recorder.AcquireEvidenceCeremonyLock(dir)
	if err != nil {
		return nil, fmt.Errorf("acquire exclusive receipt writer lock: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, lock.Close())
		}
	}()

	public := key.Public().(ed25519.PublicKey)
	coverage := opts.Coverage
	coverage.Surfaces = append([]string{}, coverage.Surfaces...)
	slices.Sort(coverage.Surfaces)
	w := &StreamWriter{
		dir: dir, key: key, signer: Digest(public), lock: lock, storage: storage,
		gate: make(chan struct{}, 1), detector: opts.Detector,
		now: opts.Clock, random: opts.Random, fileBytes: writerFileBytes,
		open: StreamOpen{
			Coverage: coverage, Writer: opts.Identity, RecorderSession: opts.RecorderSession,
			Policy:    StreamPolicy{Hash: opts.PolicyHash, Source: "writer_config"},
			SignerKey: SignerKey{Alg: "ed25519", Public: base64.StdEncoding.EncodeToString(public)},
		},
	}
	if w.now == nil {
		w.now = time.Now
	}
	if w.random == nil {
		w.random = rand.Reader
	}
	if opts.Posture != nil {
		posture := *opts.Posture
		w.open.Posture = &posture
	}
	if opts.Heartbeat < 0 || opts.Heartbeat%time.Second != 0 {
		return nil, errors.New("receipt heartbeat must be a nonnegative whole number of seconds")
	}
	if opts.Heartbeat > 0 {
		seconds := int64(opts.Heartbeat / time.Second)
		w.open.HeartbeatSeconds = &seconds
	}
	keys := append([]ed25519.PublicKey{public}, opts.PriorSignerKeys...)
	if err := w.prepareStart(ctx, keys); err != nil {
		return nil, err
	}
	if err := w.publishOpen(ctx); err != nil {
		return nil, err
	}
	if err := w.replayActionRepairs(ctx); err != nil {
		if w.active.file != nil {
			err = errors.Join(err, w.active.file.Close())
		}
		return nil, fmt.Errorf("settle pending receipt holds before admitting traffic: %w", err)
	}
	if opts.Heartbeat > 0 {
		w.startHeartbeats(opts.Heartbeat, opts.OnHeartbeatError)
	}
	return w, nil
}

// DirectoryHasV3 reports whether a v3 filename has committed the directory
// to this format. A damaged file with the suffix also requires v3 handling.
func DirectoryHasV3(dir string) (bool, error) {
	if dir == "" {
		return false, nil
	}
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read receipt evidence directory: %w", err)
	}
	return hasV3Entry(entries), nil
}

func hasV3Entry(entries []os.DirEntry) bool {
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), layoutFileSuffix) {
			return true
		}
	}
	return false
}

func (w *StreamWriter) prepareStart(ctx context.Context, keys []ed25519.PublicKey) error {
	entries, err := os.ReadDir(w.dir)
	if err != nil {
		return fmt.Errorf("read receipt evidence directory: %w", err)
	}
	if !hasV3Entry(entries) {
		return w.prepareCutover(ctx, keys, entries)
	}
	var history HistoryResult
	var head StreamResult
	opts := Options{Directory: true, DiskIndex: true, Keys: keys}
	_, err = verifyPathsInspect(ctx, []string{w.dir}, opts, "", func(v *verification) error {
		var headErr error
		history, head, headErr = startupHead(v.result, v.actionVersionNeeded)
		if headErr != nil {
			return headErr
		}
		repairs, err := v.recoverHolds(history.Lineage)
		if err != nil {
			return err
		}
		w.repairs = repairs
		return nil
	})
	if err != nil {
		return fmt.Errorf("verify receipt history before restart: %w", err)
	}
	path, err := lastStreamFile(w.dir, entries, head.Stream)
	if err != nil {
		return err
	}
	if err := w.storage.cleanup(w.dir, entries); err != nil {
		return err
	}
	if err := w.storage.syncFile(path); err != nil {
		return fmt.Errorf("re-flush predecessor receipt file: %w", err)
	}
	if err := w.storage.syncDir(w.dir); err != nil {
		return fmt.Errorf("re-flush predecessor receipt directory: %w", err)
	}
	ended := endedUnsealed
	if head.End == endedClosed {
		ended = endedClosed
	}
	w.open.Lineage = history.Lineage
	w.previous = &Previous{Stream: head.Stream, Record: head.Tip.Record, Seq: head.Tip.Seq, Ended: ended}
	return nil
}

func startupHead(result Result, neededActionVersion int64) (HistoryResult, StreamResult, error) {
	for _, finding := range result.Findings {
		if finding.Code == codeTrust {
			for _, history := range result.Histories {
				for _, stream := range history.Streams {
					if stream.Stream == finding.Stream {
						return HistoryResult{}, StreamResult{}, fmt.Errorf("receipt startup verification refused %s: configure prior signer key %s (stream %s)", codeTrust, stream.Signer, stream.Stream)
					}
				}
			}
		}
		switch finding.Code {
		case codeHistoryDisconnected, codePredecessorNotPresented, codeCutoverInventoryNotPresented,
			codeLegacyChainNotPresented:
			return HistoryResult{}, StreamResult{}, startupFinding(finding)
		}
		if finding.Class == invalid || finding.Class == unsupported {
			return HistoryResult{}, StreamResult{}, startupFinding(finding)
		}
	}
	for _, finding := range result.Findings {
		if finding.Code == codeDecisionsNotAppraised {
			return HistoryResult{}, StreamResult{}, fmt.Errorf("receipt startup verification refused %s: action body version %d required", codeDecisionsNotAppraised, neededActionVersion)
		}
	}
	for _, finding := range result.Findings {
		if finding.Code == codeActionUninterpreted {
			return HistoryResult{}, StreamResult{}, fmt.Errorf("receipt startup verification refused %s: compatible action body version %d vocabulary required", codeActionUninterpreted, wireKinds[kindAction].version)
		}
	}
	if len(result.Histories) != 1 {
		return HistoryResult{}, StreamResult{}, errors.New("receipt startup requires exactly one verified history")
	}
	history := result.Histories[0]
	predecessors := make(map[string]bool, len(history.Streams))
	for _, stream := range history.Streams {
		if stream.Tip == nil {
			return HistoryResult{}, StreamResult{}, errors.New("receipt startup found a stream without a verified tip")
		}
		predecessors[stream.Previous] = true
	}
	var head StreamResult
	for _, stream := range history.Streams {
		if predecessors[stream.Stream] {
			continue
		}
		if head.Tip != nil {
			return HistoryResult{}, StreamResult{}, errors.New("receipt startup found multiple history tips")
		}
		head = stream
	}
	if head.Tip == nil {
		return HistoryResult{}, StreamResult{}, errors.New("receipt startup found no verified history tip")
	}
	return history, head, nil
}

func startupFinding(finding Finding) error {
	return fmt.Errorf("receipt startup verification refused %s (stream %s, record %s)", finding.Code, finding.Stream, finding.Record)
}

func lastStreamFile(dir string, entries []os.DirEntry, stream string) (string, error) {
	// os.ReadDir sorts names. Equal-width starting positions sort by sequence.
	for i := len(entries) - 1; i >= 0; i-- {
		file, _ := identify(entries[i].Name())
		if file.stream == stream {
			return filepath.Join(dir, file.path), nil
		}
	}
	return "", errors.New("cannot locate the verified predecessor receipt file")
}

func (w *StreamWriter) newStreamID() (string, error) {
	var raw [16]byte
	if _, err := io.ReadFull(w.random, raw[:]); err != nil {
		return "", fmt.Errorf("generate receipt stream identity: %w", err)
	}
	return hex.EncodeToString(raw[:]), nil
}

func (w *StreamWriter) common(kind, stream, prev string, seq int64) Common {
	return Common{
		V: 3, Kind: kind, BodyV: wireKinds[kind].version, Stream: stream,
		Prev: prev, Seq: seq, Signer: w.signer, TS: w.now().UTC().Format(writerTimestampLayout),
	}
}

func (w *StreamWriter) publishOpen(ctx context.Context) error {
	stream, err := w.newStreamID()
	if err != nil {
		return err
	}
	open := w.open
	open.Previous = w.previous
	if open.Previous != nil {
		open.LegacyCutover = nil
	}
	line, record, err := w.encode(ctx, w.common(kindStreamOpen, stream, Genesis(stream), 0), open)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	file, linked, err := w.storage.publish(w.dir, writerFilename(stream, 0), line)
	if err != nil {
		if linked || errors.Is(err, fs.ErrExist) {
			// Another root or successor would leave a fork if the name
			// survived. A verified restart can see which name survived.
			w.fatal = err
		}
		return fmt.Errorf("publish receipt stream opening: %w", err)
	}
	w.active = writerStream{id: stream, confirmed: Position{Record: record}, file: file, bytes: len(line)}
	w.previous = nil
	return nil
}

func (w *StreamWriter) acquire(ctx context.Context) error {
	select {
	case w.gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			w.release()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *StreamWriter) release() {
	<-w.gate
}

func (w *StreamWriter) ensureStream(ctx context.Context) error {
	if w.closed {
		return errors.New("receipt writer is closed")
	}
	if w.fatal != nil {
		return fmt.Errorf("receipt stream publication needs a verified restart: %w", w.fatal)
	}
	if w.active.file == nil {
		return w.publishOpen(ctx)
	}
	return nil
}

func (w *StreamWriter) retire(ended string) {
	w.previous = &Previous{
		Stream: w.active.id, Seq: w.active.confirmed.Seq,
		Record: w.active.confirmed.Record, Ended: ended,
	}
	_ = w.active.file.Close()
	w.active.file = nil
}

// commit advances the confirmation point only after its write and all needed
// flushes succeed. An encoding, scan, or cancellation error writes nothing
// and leaves the stream usable.
func (w *StreamWriter) commit(ctx context.Context, kind string, body any) error {
	seq := w.active.confirmed.Seq + 1
	line, record, err := w.encode(ctx, w.common(kind, w.active.id, w.active.confirmed.Record, seq), body)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := w.persist(kind, line, seq); err != nil {
		w.durability.FsyncErrorsGated++
		w.retire(endedWriteError)
		return err
	}
	w.active.confirmed = Position{Record: record, Seq: seq}
	return nil
}

func (w *StreamWriter) persist(kind string, line []byte, seq int64) error {
	reserve := maxLineBytes
	if kind == kindStreamClose {
		reserve = 0
	}
	if w.active.bytes+len(line)+reserve > w.fileBytes {
		file, _, err := w.storage.publish(w.dir, writerFilename(w.active.id, seq), line)
		if err != nil {
			return err
		}
		_ = w.active.file.Close()
		w.active.file, w.active.bytes = file, len(line)
		return nil
	}
	if err := writeWriterLine(w.active.file, line); err != nil {
		return err
	}
	if err := w.active.file.Sync(); err != nil {
		return fmt.Errorf("flush receipt record: %w", err)
	}
	w.active.bytes += len(line)
	return nil
}

// A failed stream is retired before opening its successor. A second
// failure leaves the outstanding repairs queued for the next admission.
func (w *StreamWriter) tryContinueAfterWriteError(ctx context.Context, writeErr error) error {
	if w.previous == nil || w.previous.Ended != endedWriteError {
		return writeErr
	}
	ctx = context.WithoutCancel(ctx)
	if err := w.ensureStream(ctx); err != nil {
		return errors.Join(writeErr, err)
	}
	return errors.Join(writeErr, w.replayActionRepairs(ctx))
}

func (w *StreamWriter) prepareAppend(ctx context.Context) error {
	if err := w.replayActionRepairs(ctx); err != nil {
		return err
	}
	return w.ensureAppendSpace(ctx)
}

func (w *StreamWriter) ensureAppendSpace(ctx context.Context) error {
	if err := w.ensureStream(ctx); err != nil {
		return err
	}
	// StreamClose.records also needs to fit within the wire integer limit.
	if w.active.confirmed.Seq >= maxInteger-2 {
		return w.rollover(ctx)
	}
	return nil
}

// WriteHeartbeat records the next heartbeat after all preceding appends.
func (w *StreamWriter) WriteHeartbeat(ctx context.Context) error {
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	body := Heartbeat{
		Beat: w.active.beat + 1, DurabilityBlocks: w.durability.DurabilityBlocks,
		FsyncErrorsGated: w.durability.FsyncErrorsGated,
	}
	if err := w.commit(ctx, kindHeartbeat, body); err != nil {
		return w.tryContinueAfterWriteError(ctx, err)
	}
	w.active.beat++
	return nil
}

// Rollover closes the current stream and publishes its successor under the
// same coverage. New files may also be added to a stream without closing it.
func (w *StreamWriter) Rollover(ctx context.Context) error {
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	if err := w.prepareAppend(ctx); err != nil {
		return err
	}
	if err := w.rollover(ctx); err != nil {
		return w.tryContinueAfterWriteError(ctx, err)
	}
	return nil
}

func (w *StreamWriter) rollover(ctx context.Context) error {
	if err := w.writeClose(ctx, closeRollover, nil); err != nil {
		return err
	}
	w.retire(endedClosed)
	return w.publishOpen(ctx)
}

func (w *StreamWriter) writeClose(ctx context.Context, reason string, operational *Recorder) error {
	return w.commit(ctx, kindStreamClose, StreamClose{
		Records: w.active.confirmed.Seq + 2, Reason: reason, Durability: w.durability, Recorder: operational,
	})
}

// Close writes a shutdown record if the stream is usable and releases the
// directory lock. The optional operational binding is a snapshot.
func (w *StreamWriter) Close(ctx context.Context, operational *Recorder) error {
	if w.stopHeartbeat != nil {
		w.stopHeartbeat()
	}
	w.gate <- struct{}{}
	defer w.release()
	if w.closed {
		return w.closeErr
	}
	w.closeErr = w.replayActionRepairs(ctx)
	w.closed = true
	if w.active.file != nil && w.closeErr == nil {
		w.closeErr = w.writeClose(ctx, closeShutdown, operational)
	}
	if w.active.file != nil {
		w.closeErr = errors.Join(w.closeErr, w.active.file.Close())
		w.active.file = nil
	}
	if w.previous != nil && w.previous.Ended == endedWriteError && w.fatal == nil {
		// A failed close is part of the unconfirmed tail, even if all its
		// bytes landed. Publish a successor that identifies that tail.
		w.closeErr = errors.Join(w.closeErr, w.publishOpen(context.WithoutCancel(ctx)))
		if w.active.file != nil {
			w.closeErr = errors.Join(w.closeErr, w.active.file.Close())
			w.active.file = nil
		}
	}
	w.closeErr = errors.Join(w.closeErr, w.fatal, w.lock.Close())
	return w.closeErr
}
