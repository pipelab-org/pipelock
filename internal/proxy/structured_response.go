// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/luckyPipewrench/pipelock/internal/checker"
	"github.com/luckyPipewrench/pipelock/internal/config"
	"github.com/luckyPipewrench/pipelock/internal/scanner"
)

const (
	structuredResponseLayer    = "structured_response"
	structuredResponseEvidence = "partial: JSON V3 decoded unique strings, first-occurrence join and unique adjacent ordered pairs; whole-document wording not assessed"
)

// Sizes of the retained per-item records, taken from the types themselves.
var (
	structuredStringHeaderBytes = int64(reflect.TypeFor[string]().Size())
	structuredIndexBytes        = int64(reflect.TypeFor[int]().Size())
	structuredFlagBytes         = int64(reflect.TypeFor[bool]().Size())
	structuredPartBytes         = int64(reflect.TypeFor[checker.Part]().Size())
)

var (
	errStructuredViewBudget = errors.New("structured response views exceed response_scanning.size_exempt_scan_max_inflight_bytes")
	errStructuredDepth      = errors.New("structured response exceeds maximum inspectable JSON depth")
)

// structuredResponseInspection retains the V3 representations in checker part
// order. Completeness describes semantic coverage, not successful JSON parsing.
// No checker is called. OriginalBytes counts source bytes; SubmittedBytes counts
// every part, including overlapping synthetic views.
type structuredResponseInspection struct {
	Parts          []checker.Part
	OriginalBytes  int64
	SubmittedBytes int64
	Completeness   checker.Completeness
	sourceHash     [sha256.Size]byte
	account        *structuredResponseAccount
}

// structuredResponseAccount charges what V3 construction retains against the
// reservation that admitted the body. The body read reserved the whole
// per-response ceiling; body capacity and every retained view, index and part
// record are spent from that reservation first and then from the shared
// in-flight budget. Each allocation is charged as it is made, so a refusal can
// overshoot by the one allocation that crossed the limit. Decoder buffers,
// discarded slice growth, scanner working memory and Go runtime overhead are not
// charged. A nil account charges nothing; only offline replay uses one.
type structuredResponseAccount struct {
	budget   *sizeExemptScanBudget
	limit    int64
	unused   int64
	reserved int64
	release  func()
}

func (a *structuredResponseAccount) charge(n int64) error {
	if a == nil || n <= 0 {
		return nil
	}
	if n <= a.unused {
		a.unused -= n
		return nil
	}
	need := n - a.unused
	if !a.budget.reserveSizeExemptScanBytes(need, a.limit) {
		return errStructuredViewBudget
	}
	a.unused = 0
	a.reserved += need
	return nil
}

func extractStructuredResponse(body []byte) (*structuredResponseInspection, error) {
	return extractStructuredResponseAccounted(body, nil)
}

func extractStructuredResponseAccounted(body []byte, account *structuredResponseAccount) (*structuredResponseInspection, error) {
	texts, err := structuredJSONStrings(body, account)
	if err != nil {
		return nil, fmt.Errorf("extracting structured response: %w", err)
	}
	n := len(texts)
	// Stable index sorts mark the first occurrence of each string and of each
	// ordered adjacent pair. Adjacency uses the full sequence before dedupe.
	if err := account.charge(int64(n) * (structuredIndexBytes + 2*structuredFlagBytes)); err != nil {
		return nil, err
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int {
		return cmp.Or(strings.Compare(texts[a], texts[b]), cmp.Compare(a, b))
	})
	firstText := make([]bool, n)
	uniqueCount := 0
	for k, i := range order {
		if k == 0 || texts[order[k-1]] != texts[i] {
			firstText[i] = true
			uniqueCount++
		}
	}
	pairs := order[:0]
	for i := 1; i < n; i++ {
		pairs = append(pairs, i)
	}
	slices.SortFunc(pairs, func(a, b int) int {
		return cmp.Or(strings.Compare(texts[a-1], texts[b-1]), strings.Compare(texts[a], texts[b]), cmp.Compare(a, b))
	})
	firstPair := make([]bool, n)
	pairCount := 0
	for k, i := range pairs {
		if k == 0 || texts[pairs[k-1]-1] != texts[i-1] || texts[pairs[k-1]] != texts[i] {
			firstPair[i] = true
			pairCount++
		}
	}

	partCount := uniqueCount + 1 + pairCount
	if err := account.charge(int64(partCount) * structuredPartBytes); err != nil {
		return nil, err
	}
	inspection := &structuredResponseInspection{
		Parts:         make([]checker.Part, 0, partCount),
		OriginalBytes: int64(len(body)),
		Completeness:  checker.Completeness{Status: checker.Partial, Reason: checker.ReasonUnsupported},
		sourceHash:    sha256.Sum256(body),
		account:       account,
	}
	appendPart := func(role, representation, text string, allocated bool) error {
		id := "part-" + strconv.Itoa(len(inspection.Parts))
		size := int64(len(id))
		if allocated {
			size += int64(len(text))
		}
		if err := account.charge(size); err != nil {
			return err
		}
		inspection.Parts = append(inspection.Parts, checker.Part{ID: id, Role: role, Representation: representation, Text: text})
		inspection.SubmittedBytes += int64(len(text))
		return nil
	}
	joinBytes := int64(0)
	for i, text := range texts {
		if firstText[i] {
			joinBytes += int64(len(text)) + 1
			// Decoded strings were charged when extracted; this part shares them.
			if err := appendPart("decoded_string", "json-string/v1", text, false); err != nil {
				return nil, err
			}
		}
	}
	if joinBytes > 0 {
		joinBytes-- // No separator after the last string.
	}
	if err := account.charge(joinBytes); err != nil {
		return nil, err
	}
	var join strings.Builder
	join.Grow(int(joinBytes))
	for i, text := range texts {
		if firstText[i] {
			if i > 0 {
				join.WriteByte('\n')
			}
			join.WriteString(text)
		}
	}
	if err := appendPart("first_occurrence_join", "json-v3-newline/v1", join.String(), false); err != nil {
		return nil, err
	}
	for i := 1; i < n; i++ {
		if firstPair[i] {
			if err := appendPart("adjacent_pair", "json-v3-newline/v1", texts[i-1]+"\n"+texts[i], true); err != nil {
				return nil, err
			}
		}
	}
	return inspection, nil
}

// structuredJSONStrings applies the request DLP JSON extractor's grammar to one
// JSON value: an empty body, trailing values, truncation and nesting deeper than
// extract.MaxExtractDepth all fail. It retains decoded strings only, keys
// included, in document order; numbers, booleans and null are not wording.
// TestStructuredJSONGrammarMatchesDLPExtractor keeps the two accept sets equal.
func structuredJSONStrings(body []byte, account *structuredResponseAccount) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var texts []string
	depth := 0
	rootStarted, rootComplete := false, false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			if !rootStarted {
				return nil, errors.New("empty JSON body")
			}
			if depth > 0 || !rootComplete {
				return nil, io.ErrUnexpectedEOF
			}
			return texts, nil
		}
		if err != nil {
			return nil, err
		}
		if rootComplete {
			return nil, errors.New("multiple JSON values")
		}
		rootStarted = true
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{', '[':
				depth++
				if depth > extractJSONMaxDepth {
					return nil, errStructuredDepth
				}
			case '}', ']':
				depth--
			}
		case string:
			before := cap(texts)
			texts = append(texts, v)
			if err := account.charge(int64(len(v)) + int64(cap(texts)-before)*structuredStringHeaderBytes); err != nil {
				return nil, err
			}
		}
		if depth == 0 {
			rootComplete = true
		}
	}
}

// structuredJSONStartPossible applies RFC 8259 section 2: JSON text is optional
// space, tab, LF or CR followed by a value, and every value starts with one of
// the bytes below. A prefix that fails cannot become one JSON value, so it keeps
// the ordinary refusal without a reservation or a further upstream read.
func structuredJSONStartPossible(prefix []byte) bool {
	for _, c := range prefix {
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			continue
		case c == '{' || c == '[' || c == '"' || c == '-' || c == 't' || c == 'f' || c == 'n' || (c >= '0' && c <= '9'):
			return true
		default:
			return false
		}
	}
	return true
}

// readStructuredResponse joins the existing bounded whole-body admission. The
// views are charged against that reservation as described on
// structuredResponseAccount. Failed parsing or view admission discards every
// partial view, returns every reserved byte and retains the ordinary refusal.
func (b *sizeExemptScanBudget) readStructuredResponse(ctx context.Context, host string, prefix []byte, body io.Reader, cfg *config.Config) ([]byte, *structuredResponseInspection, sizeExemptScanRelease) {
	if ctx.Err() != nil || !structuredJSONStartPossible(prefix) {
		return nil, nil, noopSizeExemptScanRelease
	}
	full, bodyRelease, failure := b.readBoundedSizeExemptResponse(host, prefix, body, cfg.ResponseScanning.SizeExemptScanMaxBytes, cfg.ResponseScanning.SizeExemptScanMaxInflightBytes, sizeRemedies{})
	if failure != nil {
		return nil, nil, noopSizeExemptScanRelease
	}
	account := &structuredResponseAccount{
		budget: b,
		limit:  sizeExemptScanInflightLimit(cfg.ResponseScanning.SizeExemptScanMaxInflightBytes),
		unused: sizeExemptScanCeiling(cfg.ResponseScanning.SizeExemptScanMaxBytes),
	}
	account.release = sync.OnceFunc(func() {
		b.releaseSizeExemptScanBytes(account.reserved)
		bodyRelease()
	})
	var inspection *structuredResponseInspection
	err := account.charge(int64(cap(full)))
	if err == nil {
		inspection, err = extractStructuredResponseAccounted(full, account)
	}
	if err != nil || ctx.Err() != nil {
		account.release()
		return nil, nil, noopSizeExemptScanRelease
	}
	return full, inspection, account.release
}

func scanStructuredResponse(ctx context.Context, sc *scanner.Scanner, cfg *config.Config, body []byte, target string, inspection *structuredResponseInspection) scanner.ResponseScanResult {
	if inspection == nil {
		return sc.ScanResponseBodyWithSuppress(ctx, body, target, cfg.Suppress)
	}
	// Existing response policies may rewrite buffered bytes after admission.
	// Inspect the delivered representation too; stale extracted parts cannot
	// authorize it. A digest also detects rewrites that reuse the same buffer.
	// Rebuilt views are charged to the same admission.
	if inspection.sourceHash != sha256.Sum256(body) {
		current, err := extractStructuredResponseAccounted(body, inspection.account)
		if err != nil {
			return scanner.ResponseScanResult{ScanError: err.Error()}
		}
		inspection = current
	}
	result := scanner.ResponseScanResult{Clean: true}
	for _, part := range inspection.Parts {
		scanned := sc.ScanResponseWithSuppress(ctx, part.Text, target, cfg.Suppress)
		result.Clean = result.Clean && scanned.Clean
		result.Matches = append(result.Matches, scanned.Matches...)
		result.WarnedMatches = append(result.WarnedMatches, scanned.WarnedMatches...)
		result.SuppressedMatches = append(result.SuppressedMatches, scanned.SuppressedMatches...)
		result.ObservedCoreMatches = append(result.ObservedCoreMatches, scanned.ObservedCoreMatches...)
		result.StegoDetected = result.StegoDetected || scanned.StegoDetected
		result.StegoDensity = max(result.StegoDensity, scanned.StegoDensity)
		if scanned.Failed() {
			result.ScanError = scanned.ScanError
			result.Clean = false
			return result
		}
	}
	if err := ctx.Err(); err != nil {
		result.Clean = false
		result.ScanError = err.Error()
	}
	// Synthetic coordinates never authorize rewriting the original JSON. An
	// empty transformation uses each transport's existing strip-to-block guard.
	// No benign assessment is granted; the signed diagnostic names the partial
	// representation contract, independently of this delivery result.
	return result
}

// retainStructuredShieldScan merges the pre-Shield scan like retainShieldScan,
// which lets a clean scan of a Shield rewrite supply strip output. A structured
// clean is partial, so it never certifies a rewrite: strip blocks instead.
func retainStructuredShieldScan(original *scanner.ResponseScanResult, current scanner.ResponseScanResult, body []byte, inspection *structuredResponseInspection) scanner.ResponseScanResult {
	result := retainShieldScan(original, current, body)
	if inspection != nil {
		result.TransformedContent = ""
	}
	return result
}

// structuredReservedBody holds a reverse-proxy reservation until delivery ends.
// httputil.ReverseProxy closes the response body on every path after
// ModifyResponse returns, including a ModifyResponse error.
type structuredReservedBody struct {
	io.ReadCloser
	release func()
}

func (b *structuredReservedBody) Close() error {
	defer b.release()
	return b.ReadCloser.Close()
}

// holdReservationUntilBodyClose transfers release to the final response body.
// Call it deferred from ModifyResponse so it wraps whatever body that function
// leaves behind; a panic or missing body releases at once.
func holdReservationUntilBodyClose(resp *http.Response, release sizeExemptScanRelease) {
	release = sync.OnceFunc(release)
	if p := recover(); p != nil {
		release()
		panic(p)
	}
	if resp == nil || resp.Body == nil {
		release()
		return
	}
	resp.Body = &structuredReservedBody{ReadCloser: resp.Body, release: release}
}
