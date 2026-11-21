// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

package scanner

import "context"

// SharedDLPWork is exposed to external-package scanner tests only.
type SharedDLPWork struct {
	DecodeBytes, DecodedViews, MatchBytes, NormalizeBytes uint64
}

// MeasureSharedDLPWork starts with a fresh store instead of borrowing
// retained capacity from another test's scan.
func MeasureSharedDLPWork(ctx context.Context) (context.Context, func() SharedDLPWork) {
	work := &sharedDLPWork{}
	return context.WithValue(ctx, sharedDecodesKey{}, &sharedDecodes{work: work}), func() SharedDLPWork {
		return SharedDLPWork{
			DecodeBytes:    work.decodeBytes.Load(),
			DecodedViews:   work.decodedViews.Load(),
			MatchBytes:     work.matchBytes.Load(),
			NormalizeBytes: work.normalizeBytes.Load(),
		}
	}
}
