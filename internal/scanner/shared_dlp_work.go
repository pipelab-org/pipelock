// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "sync/atomic"

// sharedDLPWork measures input at the decoder, normalizer, and decoded
// matcher boundaries for a cold shared-decode store. A cache hit contributes
// no work at the boundary it avoids. Decoded views count the results admitted
// by the decoder, whether retained or not.
type sharedDLPWork struct {
	decodeBytes    atomic.Uint64
	decodedViews   atomic.Uint64
	matchBytes     atomic.Uint64
	normalizeBytes atomic.Uint64
}
