package filter

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

// Filtering Results

// Result is a sum type of all possible filtering actions.  See the following
// types as implementations:
//
//   - [*ResultAllowed]
//   - [*ResultBlocked]
//   - [*ResultModified]
type Result interface {
	// MatchedRule returns data about the matched rule and its rule list.
	MatchedRule() (id agd.FilterListID, text agd.FilterRuleText)

	// isResult is a marker method.
	isResult()
}

// ResultAllowed means that this request or response was allowed by an allowlist
// rule within the given filter list.
type ResultAllowed struct {
	List agd.FilterListID
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultAllowed)(nil)

// MatchedRule implements the Result interface for *ResultAllowed.
func (a *ResultAllowed) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return a.List, a.Rule
}

// isResult implements the Result interface for *ResultAllowed.
func (*ResultAllowed) isResult() {}

// ResultBlocked means that this request or response was blocked by a blocklist
// rule within the given filter list.
type ResultBlocked struct {
	List agd.FilterListID
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultBlocked)(nil)

// MatchedRule implements the Result interface for *ResultBlocked.
func (b *ResultBlocked) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return b.List, b.Rule
}

// isResult implements the Result interface for *ResultBlocked.
func (*ResultBlocked) isResult() {}

// ResultModified means that this request or response was rewritten or modified
// by a rewrite rule within the given filter list.
type ResultModified struct {
	// Msg is the new, rewritten or modified request or response.
	Msg *dns.Msg

	// List is the ID of the filter list.
	List agd.FilterListID

	// Rule is the filtering rule that triggered the rewrite.
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultModified)(nil)

// MatchedRule implements the Result interface for *ResultModified.
func (m *ResultModified) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return m.List, m.Rule
}

// isResult implements the Result interface for *ResultModified.
func (*ResultModified) isResult() {}

// Clone returns a deep clone of m.
func (m *ResultModified) Clone() (clone *ResultModified) {
	return &ResultModified{
		Msg:  dnsmsg.Clone(m.Msg),
		List: m.List,
		Rule: m.Rule,
	}
}

// CloneForReq returns a deep clone of m with Msg set as a reply to req, if any.
func (m *ResultModified) CloneForReq(req *dns.Msg) (clone *ResultModified) {
	msg := dnsmsg.Clone(m.Msg)

	// TODO(a.garipov): This will become invalid if Msg ever contains a
	// non-success response, which is not the case currently.  If that happens,
	// find a better way to cache as much of the response as possible.
	msg.SetReply(req)

	return &ResultModified{
		Msg:  msg,
		List: m.List,
		Rule: m.Rule,
	}
}
