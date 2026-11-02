// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"fmt"
	"io"

	"github.com/luckyPipewrench/pipelock/internal/recorder"
)

// VerifyRecorderEnd applies the whole-recorder verifier to an already-read
// snapshot. A missing authenticated endpoint returns false without an error;
// malformed seals, signatures, or recorder chains return an error. Callers
// must distinguish that valid prefix from a proven end.
func VerifyRecorderEnd(entries []recorder.Entry, trustedKeys []string) (bool, error) {
	var reports []chainCLIReport
	scan := newWholeRecorderScan(trustedKeys, verifyReceiptOptions{
		CheckEnd:      true,
		AllowUnpinned: len(trustedKeys) == 0,
		// Missing anchors are reported as an unproven end, while every
		// present signature and seal still goes through the normal checks.
		AllowUnanchoredSeal: true,
		Reports:             &reports,
	})
	defer scan.close()
	for _, entry := range entries {
		scan.add(entry)
	}
	if err := scan.whole.Err(); err != nil {
		return false, fmt.Errorf("whole-recorder integrity: %w", err)
	}
	if err := scan.report(io.Discard, "audit packet"); err != nil {
		if isPrefixError(err) {
			return false, nil
		}
		return false, err
	}
	return len(reports) == 1 && reports[0].EndProof.Proven, nil
}
