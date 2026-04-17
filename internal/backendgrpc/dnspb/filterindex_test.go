package dnspb_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/publicsuffix"
)

func TestTyposquattingFilterIndex_ToInternal(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		index      *dnspb.TyposquattingFilterIndex
		want       *filterindex.Typosquatting
		name       string
		wantErrMsg string
	}{{
		index:      nil,
		want:       nil,
		name:       "nil",
		wantErrMsg: "index: no value",
	}, {
		index: &dnspb.TyposquattingFilterIndex{},
		want: &filterindex.Typosquatting{
			Domains:    []*filterindex.TyposquattingProtectedDomain{},
			Exceptions: []*filterindex.TyposquattingException{},
		},
		name:       "empty",
		wantErrMsg: "",
	}, {
		index:      backendtest.TyposquattingIndexGRPC,
		want:       backendtest.TyposquattingIndex,
		name:       "good",
		wantErrMsg: "",
	}, {
		index: &dnspb.TyposquattingFilterIndex{
			Domains: []*dnspb.TyposquattingFilterIndex_ProtectedDomain{{
				Domain:   "!",
				Distance: 1,
			}},
			Exceptions: []*dnspb.TyposquattingFilterIndex_Exception{{
				Domain: "!",
			}},
		},
		want: nil,
		name: "bad_domains",
		wantErrMsg: `domains: at index 0: domain: publicsuffix: ` +
			`cannot derive eTLD+1 for domain "!"` + "\n" +
			`exceptions: at index 0: domain: publicsuffix: ` +
			`cannot derive eTLD+1 for domain "!"`,
	}, {
		index: &dnspb.TyposquattingFilterIndex{
			Domains: []*dnspb.TyposquattingFilterIndex_ProtectedDomain{{
				Domain:   backendtest.ETLDPlus1,
				Distance: 0,
			}},
		},
		want:       nil,
		name:       "bad_dist",
		wantErrMsg: "domains: at index 0: distance: not positive: 0",
	}, {
		index: &dnspb.TyposquattingFilterIndex{
			Domains: []*dnspb.TyposquattingFilterIndex_ProtectedDomain{{
				Domain:   "www." + backendtest.ETLDPlus1,
				Distance: 1,
			}},
		},
		want:       nil,
		name:       "not_etldplus1",
		wantErrMsg: "domains: at index 0: domain: not an etld+1 domain",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tc.index.ToInternal(publicsuffix.List)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
