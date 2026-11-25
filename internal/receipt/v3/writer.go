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
	"sync"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/receiptcontent"
	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

const (
	endedClosed              = "closed"
	endedUnsealed            = "unsealed"
	endedWriteError          = "write_error"
	closeRollover            = "rollover"
	closeShutdown            = "shutdown"
	writerConfigPolicySource = "writer_config"

	// Detached writes may outlive a request, but must release the writer gate.
	writerRepairTimeout = 5 * time.Second
)

// StreamWriterOptions captures the settings that describe a stream for its
// whole lifetime. Prior keys are used only for startup verification.
type StreamWriterOptions struct {
	Dir             string
	SigningKey      ed25519.PrivateKey
	PriorSignerKeys []ed25519.PublicKey
	Coverage        Coverage
	Identity        Writer
	PolicyHash      string
	Posture         *Posture
	RecorderSession string
	Heartbeat       time.Duration
	// OnHeartbeatError runs outside the heartbeat loop and may call Close.
	// A callback already in progress coalesces further heartbeat failures.
	OnHeartbeatError func(error)
	// OnDelayedSyncError reports a failed flush of an acknowledged outcome.
	OnDelayedSyncError func(error)
	// OnFatalError reports an unusable successor or failed repair replay.
	OnFatalError   func(error)
	idleFlushDelay *time.Duration
	Detector       receiptcontent.Detector
	Clock          func() time.Time
	Random         io.Reader

	// CreateTempFile creates a new file in dir, as os.CreateTemp does.
	// A nil factory uses the local filesystem directly.
	CreateTempFile func(dir, pattern string) (StreamFile, error)
}

type writerStream struct {
	id        string
	confirmed Position
	appended  Position
	file      StreamFile
	bytes     int
	beat      int64
}

// StreamWriter owns the evidence directory for its lifetime. It serializes
// appends, confirms captured prefixes, and never reuses a failed stream.
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

	idleFlushDelay     time.Duration
	onDelayedSyncError func(error)
	onFatalError       func(error)
	flushWake          chan struct{}
	flushStop          chan struct{}
	flushDone          chan struct{}
	closeOnce          sync.Once
	closeRequested     chan struct{}
	closeDone          chan struct{}

	// All state below is protected by gate. Only the flusher releases the
	// gate during an active-file sync.
	changed       chan struct{}
	transition    bool
	draining      bool
	syncing       bool
	pending       []*writeTicket
	ready         []*writeTicket
	waiters       int
	lastWriteErr  error
	notifications []flushNotification

	active     writerStream
	previous   *Previous
	fatal      error
	closeErr   error
	durability Durability
	repairs    []Action
	repairKeys map[repairKey]struct{}
	holds      map[string]string
}

// OpenStreamWriter verifies and re-flushes any predecessor before publishing
// a new stream. A second writer cannot inspect or mutate the directory.
func OpenStreamWriter(ctx context.Context, opts StreamWriterOptions) (*StreamWriter, error) {
	storage := localWriterStorage()
	if opts.CreateTempFile != nil {
		storage.createTemp = opts.CreateTempFile
	}
	return openStreamWriter(ctx, opts, storage)
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
		gate: make(chan struct{}, 1), detector: opts.Detector, holds: make(map[string]string),
		now: opts.Clock, random: opts.Random, fileBytes: writerFileBytes,
		idleFlushDelay:     defaultIdleFlushDelay,
		onDelayedSyncError: opts.OnDelayedSyncError, onFatalError: opts.OnFatalError,
		flushWake: make(chan struct{}, 1), flushStop: make(chan struct{}), flushDone: make(chan struct{}),
		closeRequested: make(chan struct{}), closeDone: make(chan struct{}),
		changed: make(chan struct{}), repairKeys: make(map[repairKey]struct{}),
		open: StreamOpen{
			Coverage: coverage, Writer: opts.Identity, RecorderSession: opts.RecorderSession,
			Policy:    StreamPolicy{Hash: opts.PolicyHash, Source: writerConfigPolicySource},
			SignerKey: SignerKey{Alg: "ed25519", Public: base64.StdEncoding.EncodeToString(public)},
		},
	}
	if opts.idleFlushDelay != nil {
		w.idleFlushDelay = *opts.idleFlushDelay
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
	w.gate <- struct{}{}
	repairErr := w.replayActionRepairs(ctx, true)
	w.release()
	if repairErr != nil {
		if w.active.file != nil {
			repairErr = errors.Join(repairErr, w.active.file.Close())
		}
		return nil, fmt.Errorf("settle pending receipt holds before admitting traffic: %w", repairErr)
	}
	go w.runFlusher()
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
		for _, repair := range repairs {
			w.enqueueRepair(repair)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("verify receipt history before restart: %w", err)
	}
	if err := w.storage.cleanup(w.dir, entries); err != nil {
		return err
	}
	// Overlapping verified segments may start later and end before the tip.
	foundPredecessor := false
	for _, entry := range entries {
		file, _ := identify(entry.Name())
		if file.stream == head.Stream {
			foundPredecessor = true
			if err := w.storage.syncFile(filepath.Join(w.dir, file.path)); err != nil {
				return fmt.Errorf("re-flush predecessor receipt file: %w", err)
			}
		}
	}
	if !foundPredecessor {
		return errors.New("cannot locate the verified predecessor receipt file")
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
	var incompleteFinding Finding
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
		switch finding.Class {
		case invalid, unsupported:
			return HistoryResult{}, StreamResult{}, startupFinding(finding)
		case incomplete:
			// A newer body version takes priority over an unknown value
			// in the current version when both compatibility findings apply.
			if incompleteFinding.Code == "" || finding.Code == codeDecisionsNotAppraised {
				incompleteFinding = finding
			}
		}
	}
	if incompleteFinding.Code != "" {
		return HistoryResult{}, StreamResult{}, startupIncompleteFinding(incompleteFinding, neededActionVersion)
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

func startupIncompleteFinding(finding Finding, neededActionVersion int64) error {
	base := startupFinding(finding)
	const newHistory = "preserve this directory and start in a new empty evidence directory"
	switch finding.Code {
	case codeDecisionsNotAppraised:
		return fmt.Errorf("%w: action body version %d required. Use a compatible release or %s", base, neededActionVersion, newHistory)
	case codeActionUninterpreted:
		return fmt.Errorf("%w: compatible action body version %d vocabulary required. Use a compatible release or %s", base, wireKinds[kindAction].version, newHistory)
	case codeNoEvidence:
		return fmt.Errorf("%w: supply the directory containing the v3 receipt files", base)
	case codeDecisionIndexFull:
		return fmt.Errorf("%w: %s. Use a verifier that can appraise all decisions to inspect the original history", base, newHistory)
	default:
		return fmt.Errorf("%w: restore the complete evidence from a trusted copy and retry, or %s", base, newHistory)
	}
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
	tip := Position{Record: record}
	w.active = writerStream{id: stream, confirmed: tip, appended: tip, file: file, bytes: len(line)}
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

// ErrWriterUnavailable means writes cannot resume on this writer.
var ErrWriterUnavailable = errors.New("receipt writer is unavailable")

var errWriterNeedsRestart = errors.New("receipt writer needs a verified restart")

func (w *StreamWriter) ensureStream(ctx context.Context) error {
	if w.fatal != nil {
		return errors.Join(ErrWriterUnavailable, errWriterNeedsRestart, w.fatal)
	}
	if w.active.file == nil {
		err := w.publishOpen(ctx)
		if err != nil && w.fatal != nil && !w.failed() {
			w.reportFatal(err)
		}
		return err
	}
	return nil
}

func (w *StreamWriter) retire(ended string) {
	w.previous = &Previous{
		Stream: w.active.id, Seq: w.active.confirmed.Seq,
		Record: w.active.confirmed.Record, Ended: ended,
	}
	if !w.syncing {
		_ = w.active.file.Close()
	}
	w.active.file = nil
}

var errRecordVisible = errors.New("receipt record visible before durability failure")

func (w *StreamWriter) needsSegment(kind string, size int) bool {
	reserve := maxLineBytes
	if kind == kindStreamClose {
		reserve = 0
	}
	return w.active.bytes+size+reserve > w.fileBytes
}

func (w *StreamWriter) appendRecord(ctx context.Context, kind string, body any, ticket *writeTicket) error {
	for {
		before := w.active.appended
		seq := before.Seq + 1
		line, record, err := w.encode(ctx, w.common(kind, w.active.id, before.Record, seq), body)
		if err != nil {
			return err
		}
		if w.needsSegment(kind, len(line)) && before != w.active.confirmed {
			if err := w.drainSegment(ctx); err != nil {
				return err
			}
			if before != w.active.appended {
				continue
			}
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return w.appendLines(kind, line, seq, Position{Record: record, Seq: seq}, ticket)
	}
}

// appendLines writes a single record or a whole admission range. A later
// segment starts with a confirmed prefix in the previous file.
func (w *StreamWriter) appendLines(kind string, line []byte, first int64, tip Position, ticket *writeTicket) error {
	var err error
	newSegment := w.needsSegment(kind, len(line))
	if newSegment {
		var file StreamFile
		var linked bool
		file, linked, err = w.storage.publish(w.dir, writerFilename(w.active.id, first), line)
		if err == nil {
			_ = w.active.file.Close()
			w.active.file, w.active.bytes = file, 0
		} else if linked {
			err = errors.Join(errRecordVisible, err)
		}
	} else {
		err = writeWriterLine(w.active.file, line)
	}
	if err != nil {
		if ticket != nil {
			ticket.visible = errors.Is(err, errRecordVisible)
			w.pending = append(w.pending, ticket)
		}
		w.failGeneration(err, false)
		if ticket != nil {
			return w.waitTicket(ticket)
		}
		return err
	}
	w.active.bytes += len(line)
	w.active.appended = tip
	if ticket != nil {
		ticket.visible = true
		w.registerTicket(ticket, tip)
	}
	// publish confirmed the first record or batch with both flush barriers.
	if newSegment {
		w.confirmThrough(tip)
		w.releaseReady()
	}
	return nil
}

func (w *StreamWriter) waitForAppend(ctx context.Context) error {
	if err := w.waitState(ctx, func() bool {
		return w.fatal == nil && (w.transition || w.failed() || len(w.repairs) != 0)
	}); err != nil {
		return err
	}
	if w.fatal != nil {
		return w.ensureStream(ctx)
	}
	select {
	case <-w.closeRequested:
		return fmt.Errorf("%w: closed", ErrWriterUnavailable)
	default:
	}
	return w.ensureStream(ctx)
}

func (w *StreamWriter) prepareAppend(ctx context.Context, records int64) error {
	if err := w.waitForAppend(ctx); err != nil {
		return err
	}
	// A pending gate may need one settlement per record before rollover.
	// Leave room for those records and StreamClose.records within the wire limit.
	unconfirmed := w.active.appended.Seq - w.active.confirmed.Seq
	available := maxInteger - 2 - w.active.appended.Seq - unconfirmed
	if records > available/2 {
		return w.rollover(ctx)
	}
	return nil
}

// WriteHeartbeat reserves the next beat in append order and waits for its
// confirmation.
func (w *StreamWriter) WriteHeartbeat(ctx context.Context) error {
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	if err := w.prepareAppend(ctx, 1); err != nil {
		return err
	}
	ticket := newWriteTicket(ctx, nil, writeConfirmed)
	// Segment drainage can release the gate. The transition reserves this
	// beat until the heartbeat is appended.
	body := Heartbeat{
		Beat: w.active.beat + 1, DurabilityBlocks: w.durability.DurabilityBlocks,
		FsyncErrorsGated: w.durability.FsyncErrorsGated,
	}
	if err := w.appendRecord(ctx, kindHeartbeat, body, ticket); err != nil {
		return err
	}
	w.active.beat++
	return w.waitTicket(ticket)
}

// Rollover closes the current stream and publishes its successor under the
// same coverage. New files may also be added to a stream without closing it.
func (w *StreamWriter) Rollover(ctx context.Context) error {
	if err := w.acquire(ctx); err != nil {
		return err
	}
	defer w.release()
	if err := w.waitForAppend(ctx); err != nil {
		return err
	}
	return w.rollover(ctx)
}

func (w *StreamWriter) rollover(ctx context.Context) error {
	w.transition = true
	defer func() {
		w.transition = false
		w.notifyChange()
	}()
	if err := w.drainForEnd(ctx, false); err != nil {
		return err
	}
	if err := w.writeClose(ctx, closeRollover, nil); err != nil {
		return err
	}
	w.retire(endedClosed)
	return w.ensureStream(ctx)
}

func (w *StreamWriter) drainForEnd(ctx context.Context, outcomes bool) error {
	w.draining = outcomes
	defer func() { w.draining = false }()
	before := w.durability.FsyncErrorsGated
	w.wakeFlush()
	if err := w.waitState(ctx, func() bool { return w.fatal == nil && w.busy(outcomes) }); err != nil {
		return err
	}
	if before != w.durability.FsyncErrorsGated {
		return errors.Join(w.lastWriteErr, w.fatal)
	}
	return w.fatal
}

func (w *StreamWriter) writeClose(ctx context.Context, reason string, operational *Recorder) error {
	ticket := newWriteTicket(ctx, nil, writeConfirmed)
	if err := w.appendRecord(ctx, kindStreamClose, StreamClose{
		Records: w.active.appended.Seq + 2, Reason: reason, Durability: w.durability, Recorder: operational,
	}, ticket); err != nil {
		return err
	}
	return w.waitTicket(ticket)
}

// Close writes a shutdown record if the stream is usable and releases the
// directory lock. The optional operational binding is a snapshot.
func (w *StreamWriter) Close(ctx context.Context, operational *Recorder) error {
	w.startClose(ctx, operational, true)
	<-w.closeDone
	return w.closeErr
}

// CloseUnsealed drains accepted records without signing a clean end. If a
// file operation outlasts the deadline, cleanup retains ownership of the
// directory until that operation returns.
func (w *StreamWriter) CloseUnsealed(ctx context.Context) error {
	w.startClose(ctx, nil, false)
	ctx, cancel := context.WithTimeout(ctx, writerRepairTimeout)
	defer cancel()
	select {
	case <-w.closeDone:
		return w.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *StreamWriter) startClose(ctx context.Context, operational *Recorder, seal bool) {
	w.closeOnce.Do(func() {
		close(w.closeRequested)
		go w.finishClose(ctx, operational, seal)
	})
}

func (w *StreamWriter) finishClose(ctx context.Context, operational *Recorder, seal bool) {
	defer close(w.closeDone)
	if w.stopHeartbeat != nil {
		w.stopHeartbeat()
	}
	w.gate <- struct{}{}
	_ = w.waitState(context.Background(), func() bool { return w.transition })
	w.transition = true
	w.closeErr = w.drainForEnd(context.Background(), !seal)
	if seal && w.closeErr == nil && w.active.file != nil {
		w.closeErr = w.writeClose(ctx, closeShutdown, operational)
		if w.closeErr != nil && w.fatal == nil && len(w.pending) != 0 {
			w.closeErr = errors.Join(w.closeErr, w.drainForEnd(context.Background(), true))
		}
	}
	if w.active.file != nil {
		w.closeErr = errors.Join(w.closeErr, w.active.file.Close())
		w.active.file = nil
	}
	w.transition = false
	w.notifyChange()
	close(w.flushStop)
	w.release()
	<-w.flushDone
	w.closeErr = errors.Join(w.closeErr, w.lock.Close())
}
