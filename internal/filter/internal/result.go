package internal

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
//   - [*ResultModifiedResponse]
//   - [*ResultModifiedRequest]
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

// MatchedRule implements the [Result] interface for *ResultAllowed.
func (a *ResultAllowed) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return a.List, a.Rule
}

// isResult implements the [Result] interface for *ResultAllowed.
func (*ResultAllowed) isResult() {}

// ResultBlocked means that this request or response was blocked by a blocklist
// rule within the given filter list.
type ResultBlocked struct {
	List agd.FilterListID
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultBlocked)(nil)

// MatchedRule implements the [Result] interface for *ResultBlocked.
func (b *ResultBlocked) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return b.List, b.Rule
}

// isResult implements the [Result] interface for *ResultBlocked.
func (*ResultBlocked) isResult() {}

// ResultModifiedResponse means that this response was rewritten or modified by
// a rewrite rule within the given filter list.
type ResultModifiedResponse struct {
	// Msg is the new, rewritten or modified response.
	Msg *dns.Msg

	// List is the ID of the filter list.
	List agd.FilterListID

	// Rule is the filtering rule that triggered the rewrite.
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultModifiedResponse)(nil)

// MatchedRule implements the [Result] interface for *ResultModifiedResponse.
func (m *ResultModifiedResponse) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return m.List, m.Rule
}

// isResult implements the [Result] interface for *ResultModifiedResponse.
func (*ResultModifiedResponse) isResult() {}

// Clone returns a deep clone of m.
func (m *ResultModifiedResponse) Clone(c *dnsmsg.Cloner) (clone *ResultModifiedResponse) {
	msg := c.Clone(m.Msg)

	return &ResultModifiedResponse{
		Msg:  msg,
		List: m.List,
		Rule: m.Rule,
	}
}

// CloneForReq returns a deep clone of m with Msg set as a reply to req, if any.
func (m *ResultModifiedResponse) CloneForReq(
	c *dnsmsg.Cloner,
	req *dns.Msg,
) (clone *ResultModifiedResponse) {
	msg := c.Clone(m.Msg)

	// TODO(a.garipov): This will become invalid if Msg ever contains a
	// non-success response, which is not the case currently.  If that happens,
	// find a better way to cache as much of the response as possible.
	msg.SetReply(req)

	return &ResultModifiedResponse{
		Msg:  msg,
		List: m.List,
		Rule: m.Rule,
	}
}

// ResultModifiedRequest means that this request was rewritten or modified by a
// rewrite rule within the given filter list.
type ResultModifiedRequest struct {
	// Msg is the new, rewritten or modified request.
	Msg *dns.Msg

	// List is the ID of the filter list.
	List agd.FilterListID

	// Rule is the filtering rule that triggered the rewrite.
	Rule agd.FilterRuleText
}

// type check
var _ Result = (*ResultModifiedRequest)(nil)

// MatchedRule implements the [Result] interface for *ResultModifiedRequest.
func (m *ResultModifiedRequest) MatchedRule() (id agd.FilterListID, text agd.FilterRuleText) {
	return m.List, m.Rule
}

// isResult implements the [Result] interface for *ResultModifiedRequest.
func (*ResultModifiedRequest) isResult() {}

// Clone returns a deep clone of m with a new ID.
func (m *ResultModifiedRequest) Clone(c *dnsmsg.Cloner) (clone *ResultModifiedRequest) {
	msg := c.Clone(m.Msg)
	msg.Id = dns.Id()

	return &ResultModifiedRequest{
		Msg:  msg,
		List: m.List,
		Rule: m.Rule,
	}
}
