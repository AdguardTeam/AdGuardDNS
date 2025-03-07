package filtertest

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// AssertEqualResult is a test helper that compares two results taking
// [filter.ResultModifiedRequest] and its difference in IDs into account.
func AssertEqualResult(tb testing.TB, want, got filter.Result) (ok bool) {
	tb.Helper()

	wantRM, ok := want.(*filter.ResultModifiedRequest)
	if !ok {
		return assert.Equal(tb, want, got)
	}

	gotRM := testutil.RequireTypeAssert[*filter.ResultModifiedRequest](tb, got)

	return assert.Equal(tb, wantRM.List, gotRM.List) &&
		assert.Equal(tb, wantRM.Rule, gotRM.Rule) &&
		assertEqualRequests(tb, wantRM.Msg, gotRM.Msg)
}

// assertEqualRequests is a test helper that compares two DNS requests ignoring
// the ID.
//
// TODO(a.garipov): Move to golibs?
func assertEqualRequests(tb testing.TB, want, got *dns.Msg) (ok bool) {
	tb.Helper()

	if want == nil {
		return assert.Nil(tb, got)
	}

	// Use a shallow clone, because this should be enough to fix the ID.
	gotWithID := &dns.Msg{}
	*gotWithID = *got
	gotWithID.Id = want.Id

	return assert.Equal(tb, want, gotWithID)
}

// NewRequest returns a new filtering request with the given data.
func NewRequest(
	tb testing.TB,
	cliName string,
	host string,
	ip netip.Addr,
	qt dnsmsg.RRType,
) (req *filter.Request) {
	tb.Helper()

	dnsReq := &dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  qt,
			Qclass: dns.ClassINET,
		}},
	}

	return &filter.Request{
		DNS:        dnsReq,
		Messages:   agdtest.NewConstructor(tb),
		RemoteIP:   ip,
		ClientName: cliName,
		Host:       host,
		QType:      qt,
		QClass:     dns.ClassINET,
	}
}

// NewARequest is like [NewRequest] but cliName is always empty, ip is always
// [IPv4Client], and qt is always [dns.TypeA].
func NewARequest(tb testing.TB, host string) (req *filter.Request) {
	tb.Helper()

	return NewRequest(tb, "", host, IPv4Client, dns.TypeA)
}
