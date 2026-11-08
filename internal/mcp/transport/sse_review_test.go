package transport

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func TestReviewCRBoundaryDoesNotWaitForAnotherRead(t *testing.T) {
	split := newSSELineSplitter()
	advance, token, err := split([]byte("data: x\r"), false)
	if err != nil || advance != 8 || string(token) != "data: x" {
		t.Fatalf("CR boundary: advance=%d token=%q err=%v", advance, token, err)
	}
	advance, token, err = split([]byte("\r"), false)
	if err != nil || advance != 1 || token == nil || len(token) != 0 {
		t.Fatalf("blank CR boundary: advance=%d token=%q err=%v", advance, token, err)
	}
}

// A complete CR-delimited event must arrive while the upstream is still open.
func TestReviewCRDelimitedLiveEvent(t *testing.T) {
	reader, writer := net.Pipe()
	defer func() { _ = reader.Close() }()
	defer func() { _ = writer.Close() }()
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(writer, "data: x\r\r")
		writeDone <- err
	}()
	type result struct {
		data []byte
		err  error
	}
	readDone := make(chan result, 1)
	go func() {
		data, err := NewSSEReader(reader).ReadMessage()
		readDone <- result{data, err}
	}()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case got := <-readDone:
		if got.err != nil || string(got.data) != "x" {
			t.Fatalf("got %q, %v; want x before upstream closes", got.data, got.err)
		}
	case <-timer.C:
		t.Fatal("complete CR-delimited event was not delivered while upstream stayed open")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestReviewSplitCRLFNoExtraBoundary(t *testing.T) {
	split := newSSELineSplitter()
	advance, token, err := split([]byte("a\r"), false)
	if advance != 2 || string(token) != "a" || err != nil {
		t.Fatalf("first: %d %q %v", advance, token, err)
	}
	advance, token, err = split([]byte("\n"), true)
	if advance != 1 || token != nil || err != nil {
		t.Fatalf("continuation: %d %q %v", advance, token, err)
	}
}

func TestReviewEmptyAndBOMStreams(t *testing.T) {
	for _, input := range []string{"", "\xef", "\xef\xbb", "\xef\xbb\xbf"} {
		_, err := NewSSEReader(iotest.OneByteReader(strings.NewReader(input))).ReadMessage()
		if !errors.Is(err, io.EOF) {
			t.Fatalf("%q: got %v, want EOF", input, err)
		}
	}
}

func TestReviewLineLimit(t *testing.T) {
	for _, tc := range []struct {
		n         int
		wantError bool
	}{
		{MaxLineSize - 1, false},
		{MaxLineSize, true},
	} {
		input := ":" + strings.Repeat("x", tc.n-1) + "\r"
		_, err := NewSSEReader(strings.NewReader(input)).ReadMessage()
		if tc.wantError && (!errors.Is(err, ErrIncompleteResponse) || !errors.Is(err, bufio.ErrTooLong)) {
			t.Fatalf("length %d: got %v, want incomplete response", tc.n, err)
		}
		if !tc.wantError && !errors.Is(err, io.EOF) {
			t.Fatalf("length %d: got %v, want EOF", tc.n, err)
		}
	}
}
