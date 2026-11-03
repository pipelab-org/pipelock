package scanner

import (
	"context"
	"strconv"
	"sync"
)

// inboundStructuralViewBudget bounds the bytes of view text the clean-view
// memo may hold. It is a memory bound, not a detection threshold: a view that
// does not fit is scanned in full every time.
const inboundStructuralViewBudget = 1 << 20

// inboundCleanViews remembers structural inbound views (JSON object keys and
// envelope strings) whose full DLP scan completed with no finding of any kind.
// Those views repeat across nearly every response from a server, and the scan
// is a pure function of the view and this Scanner's configuration: a reload
// builds a new Scanner and so a new memo. Only an empty, complete result is
// remembered, so a hit never suppresses a match, a warn emission, or an
// incomplete verdict.
type inboundCleanViews struct {
	mu    sync.RWMutex
	views map[string]struct{}
	bytes int
}

// inboundCleanViewKey length-prefixes the text so no pair of views, including
// views that contain the separator, can share a key.
func inboundCleanViewKey(text, cardView string) string {
	return strconv.Itoa(len(text)) + ":" + text + cardView
}

func (c *inboundCleanViews) has(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.views[key]
	return ok
}

func (c *inboundCleanViews) remember(key string) {
	if len(key) > inboundStructuralViewBudget {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.views[key]; ok {
		return
	}
	if c.views == nil || c.bytes+len(key) > inboundStructuralViewBudget {
		c.views = make(map[string]struct{})
		c.bytes = 0
	}
	c.views[key] = struct{}{}
	c.bytes += len(key)
}

// scanContextCarriesAllowance reports whether ctx holds a per-request
// allowance that can change a DLP verdict for the same text. Such scans are
// neither answered from nor recorded in the clean-view memo.
func scanContextCarriesAllowance(ctx context.Context) bool {
	return ctx.Value(oauthAuthorizationMethodKey{}) != nil ||
		ctx.Value(oauthAuthorizationPolicyKey{}) != nil ||
		ctx.Value(oauthAuthorizationAllowanceKey{}) != nil ||
		ctx.Value(issuerQueryAllowanceContextKey{}) != nil ||
		ctx.Value(issuerPathAllowanceContextKey{}) != nil ||
		ctx.Value(issuerSegmentAllowanceContextKey{}) != nil
}

// ScanTextForDLPInboundStructuralView scans an inbound JSON object key or
// envelope view with the same semantics as
// ScanTextForDLPInboundWithTypedCardView. A view this Scanner already scanned
// clean, with no finding of any kind, is answered without rescanning.
func (s *Scanner) ScanTextForDLPInboundStructuralView(ctx context.Context, text, cardView string) TextDLPResult {
	memo := ctx != nil && !scanContextCarriesAllowance(ctx)
	key := ""
	if memo {
		key = inboundCleanViewKey(text, cardView)
		if s.inboundCleanViews.has(key) {
			if ctx.Err() != nil {
				return TextDLPResult{Incomplete: true}
			}
			return TextDLPResult{Clean: true}
		}
	}
	result := s.ScanTextForDLPInboundWithTypedCardView(ctx, text, cardView)
	if memo && result.Clean && !result.Incomplete && len(result.Matches) == 0 && len(result.InformationalMatches) == 0 {
		s.inboundCleanViews.remember(key)
	}
	return result
}
