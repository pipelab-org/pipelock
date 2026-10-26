// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package runtime

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/luckyPipewrench/pipelock/internal/sdnotify"
)

// sdNotify shares the wire protocol with containment; reload policy stays here.
func sdNotify(state string) (bool, error) { return sdnotify.Send(state) }

func sdNotifyOrLog(stderr io.Writer, state string) {
	if _, err := sdNotify(state); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: %v\n", err)
	}
}

func sdNotifyReloading(stderr io.Writer) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: read monotonic clock: %v\n", err)
		return
	}
	sdNotifyOrLog(stderr, fmt.Sprintf("RELOADING=1\nMONOTONIC_USEC=%d", ts.Nano()/int64(time.Microsecond)))
}

// sdNotifyStatusMaxBytes bounds the reason text that rides in the completion
// datagram. The reason is derived from configuration the operator controls, so
// it is unbounded at the source; a datagram too large for the socket fails to
// send, and READY travels in that same datagram, so an oversized status would
// cost the completion systemd is waiting on. The operator log keeps the
// untruncated error either way.
const sdNotifyStatusMaxBytes = 256

func sdNotifyReloadComplete(stderr io.Writer, reloadErr error) {
	status := "config reload applied"
	if reloadErr != nil {
		status = "config reload rejected: " + sdNotifyStatusReason(reloadErr)
	}
	sdNotifyConfigComplete(stderr, status)
}

func sdNotifyConfigComplete(stderr io.Writer, status string) {
	if _, err := sdNotify("READY=1\nSTATUS=" + status); err != nil {
		_, _ = fmt.Fprintf(stderr, "pipelock: systemd notification failed: %v\n", err)
		// Belt and braces: retry the completion on its own. Whatever made the
		// combined datagram unsendable, systemd is still waiting for READY and
		// the reload job must not hang on a status string.
		sdNotifyOrLog(stderr, "READY=1")
	}
}

// sdNotifyStatusReason renders an error as one bounded, control-character-free
// line fit for a systemd status field.
func sdNotifyStatusReason(err error) string {
	return sdNotifySafeStatus(err.Error())
}

func sdNotifySafeStatus(text string) string {
	reason := strings.SplitN(text, "\n", 2)[0]
	reason = strings.TrimPrefix(reason, "rejected: ")
	// Printability, not a byte range. A range check that keeps everything at or
	// above 0x20 lets the C1 controls through (U+0080-U+009F, including the
	// U+009B escape introducer), along with NEL and the Unicode line and
	// paragraph separators, all of which can still steer a terminal reading
	// systemd status or an audit log. unicode.IsPrint excludes every control
	// character in both ranges and keeps ordinary ASCII space.
	reason = strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) {
			return r
		}
		return ' '
	}, reason)
	reason = strings.TrimSpace(reason)
	if len(reason) > sdNotifyStatusMaxBytes {
		reason = strings.ToValidUTF8(reason[:sdNotifyStatusMaxBytes], "") + "..."
	}
	return reason
}
