package filtertest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// AssertEqualResult is a test helper that compares two results taking
// [internal.ResultModifiedRequest] and its difference in IDs into account.
func AssertEqualResult(tb testing.TB, want, got internal.Result) (ok bool) {
	tb.Helper()

	wantRM, ok := want.(*internal.ResultModifiedRequest)
	if !ok {
		return assert.Equal(tb, want, got)
	}

	gotRM := testutil.RequireTypeAssert[*internal.ResultModifiedRequest](tb, got)

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
) (req *internal.Request) {
	tb.Helper()

	dnsReq := &dns.Msg{
		Question: []dns.Question{{
			Name:   dns.Fqdn(host),
			Qtype:  qt,
			Qclass: dns.ClassINET,
		}},
	}

	// TODO(a.garipov):  Use [agdtest.NewConstructor] when the import cycle is
	// resolved.
	msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:       dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{}),
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		StructuredErrors: &dnsmsg.StructuredDNSErrorsConfig{
			Enabled: false,
		},
		FilteredResponseTTL: 10 * time.Second,
		EDEEnabled:          false,
	})
	require.NoError(tb, err)

	return &internal.Request{
		DNS:        dnsReq,
		Messages:   msgs,
		RemoteIP:   ip,
		ClientName: cliName,
		Host:       host,
		QType:      qt,
		QClass:     dns.ClassINET,
	}
}

// NewARequest is like [NewRequest] but cliName is always empty, ip is always
// [IPv4Client], and qt is always [dns.TypeA].
func NewARequest(tb testing.TB, host string) (req *internal.Request) {
	tb.Helper()

	return NewRequest(tb, "", host, IPv4Client, dns.TypeA)
}
