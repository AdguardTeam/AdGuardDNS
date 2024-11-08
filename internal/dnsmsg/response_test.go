package dnsmsg_test

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConstructor_NewBlockedResp_nullIP(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)
	reqExtra := dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	}

	filteredSDE := dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeFiltered,
		ExtraText: agdtest.SDEText,
	})

	testCases := []struct {
		name      string
		wantAns   []dns.RR
		wantExtra []dns.RR
		qt        dnsmsg.RRType
	}{{
		name: "a",
		wantAns: []dns.RR{dnsservertest.NewA(
			testFQDN, agdtest.FilteredResponseTTLSec, netip.IPv4Unspecified(),
		)},
		wantExtra: []dns.RR{filteredSDE},
		qt:        dns.TypeA,
	}, {
		name: "aaaa",
		wantAns: []dns.RR{dnsservertest.NewAAAA(
			testFQDN, agdtest.FilteredResponseTTLSec, netip.IPv6Unspecified(),
		)},
		wantExtra: []dns.RR{filteredSDE},
		qt:        dns.TypeAAAA,
	}, {
		name:      "txt",
		wantAns:   nil,
		wantExtra: []dns.RR{filteredSDE},
		qt:        dns.TypeTXT,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req := dnsservertest.NewReq(testFQDN, tc.qt, dns.ClassINET, reqExtra)

			resp, respErr := msgs.NewBlockedResp(req)
			require.NoError(t, respErr)
			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, tc.wantAns, resp.Answer)
			assert.Equal(t, tc.wantExtra, resp.Extra)
		})
	}
}

func TestConstructor_NewBlockedResp_customIP(t *testing.T) {
	t.Parallel()

	cloner := agdtest.NewCloner()

	// TODO(a.garipov):  Test the forged extra as well if the EDE with that code
	// is used again.
	reqExtra := dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	}
	filteredExtra := dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeFiltered,
		ExtraText: agdtest.SDEText,
	})

	ansA := dnsservertest.NewA(testFQDN, agdtest.FilteredResponseTTLSec, testIPv4)
	ansAAAA := dnsservertest.NewAAAA(testFQDN, agdtest.FilteredResponseTTLSec, testIPv6)

	testCases := []struct {
		blockingMode  dnsmsg.BlockingMode
		name          string
		wantAnsA      []dns.RR
		wantAnsAAAA   []dns.RR
		wantExtraA    []dns.RR
		wantExtraAAAA []dns.RR
	}{{
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
			IPv6: []netip.Addr{testIPv6},
		},
		name:          "both",
		wantAnsA:      []dns.RR{ansA},
		wantAnsAAAA:   []dns.RR{ansAAAA},
		wantExtraA:    nil,
		wantExtraAAAA: nil,
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
		},
		name:          "ipv4_only",
		wantAnsA:      []dns.RR{ansA},
		wantAnsAAAA:   nil,
		wantExtraA:    nil,
		wantExtraAAAA: []dns.RR{filteredExtra},
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv6: []netip.Addr{testIPv6},
		},
		name:          "ipv6_only",
		wantAnsA:      nil,
		wantAnsAAAA:   []dns.RR{ansAAAA},
		wantExtraA:    []dns.RR{filteredExtra},
		wantExtraAAAA: nil,
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{},
			IPv6: []netip.Addr{},
		},
		name:          "empty",
		wantAnsA:      nil,
		wantAnsAAAA:   nil,
		wantExtraA:    []dns.RR{filteredExtra},
		wantExtraAAAA: []dns.RR{filteredExtra},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
				Cloner:              cloner,
				BlockingMode:        tc.blockingMode,
				StructuredErrors:    agdtest.NewSDEConfig(true),
				FilteredResponseTTL: agdtest.FilteredResponseTTL,
				EDEEnabled:          true,
			})
			require.NoError(t, err)

			t.Run("a", func(t *testing.T) {
				t.Parallel()

				req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET, reqExtra)
				resp, respErr := msgs.NewBlockedResp(req)
				require.NoError(t, respErr)
				require.NotNil(t, resp)

				assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
				assert.Equal(t, tc.wantAnsA, resp.Answer)
				assert.Equal(t, tc.wantExtraA, resp.Extra)
			})

			t.Run("aaaa", func(t *testing.T) {
				t.Parallel()

				req := dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET, reqExtra)
				resp, respErr := msgs.NewBlockedResp(req)
				require.NoError(t, respErr)
				require.NotNil(t, resp)

				assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
				assert.Equal(t, tc.wantAnsAAAA, resp.Answer)
				assert.Equal(t, tc.wantExtraAAAA, resp.Extra)
			})
		})
	}
}

func TestConstructor_NewBlockedResp_nodata(t *testing.T) {
	t.Parallel()

	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	})
	cloner := agdtest.NewCloner()

	wantExtra := []dns.RR{dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeFiltered,
		ExtraText: agdtest.SDEText,
	})}

	testCases := []struct {
		blockingMode dnsmsg.BlockingMode
		name         string
		rcode        dnsmsg.RCode
	}{{
		blockingMode: &dnsmsg.BlockingModeNXDOMAIN{},
		name:         "nxdomain",
		rcode:        dns.RcodeNameError,
	}, {
		blockingMode: &dnsmsg.BlockingModeREFUSED{},
		name:         "refused",
		rcode:        dns.RcodeRefused,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
				Cloner:              cloner,
				BlockingMode:        tc.blockingMode,
				StructuredErrors:    agdtest.NewSDEConfig(true),
				FilteredResponseTTL: agdtest.FilteredResponseTTL,
				EDEEnabled:          true,
			})
			require.NoError(t, err)

			resp, err := msgs.NewBlockedResp(req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, tc.rcode, dnsmsg.RCode(resp.Rcode))
			assert.Empty(t, resp.Answer)

			require.Len(t, resp.Ns, 1)

			nsTTL := resp.Ns[0].Header().Ttl
			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), nsTTL)

			assert.Equal(t, wantExtra, resp.Extra)
		})
	}
}

func TestConstructor_NewBlockedResp_sde(t *testing.T) {
	t.Parallel()

	reqEDNS := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	})
	reqNoEDNS := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)

	wantAns := []dns.RR{
		dnsservertest.NewA(testFQDN, agdtest.FilteredResponseTTLSec, netip.IPv4Unspecified()),
	}

	testCases := []struct {
		req       *dns.Msg
		sde       *dnsmsg.StructuredDNSErrorsConfig
		name      string
		wantExtra []dns.RR
		ede       bool
	}{{
		req:  reqEDNS,
		sde:  agdtest.NewSDEConfig(true),
		name: "ede_sde",
		wantExtra: []dns.RR{
			dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{
				InfoCode:  dns.ExtendedErrorCodeFiltered,
				ExtraText: agdtest.SDEText,
			}),
		},
		ede: true,
	}, {
		req:  reqEDNS,
		sde:  agdtest.NewSDEConfig(false),
		name: "ede_no_sde",
		wantExtra: []dns.RR{
			dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{
				InfoCode: dns.ExtendedErrorCodeFiltered,
			}),
		},
		ede: true,
	}, {
		req:       reqEDNS,
		sde:       agdtest.NewSDEConfig(false),
		name:      "no_ede",
		wantExtra: nil,
		ede:       false,
	}, {
		req:       reqNoEDNS,
		sde:       agdtest.NewSDEConfig(true),
		name:      "unsupported_ede_sde",
		wantExtra: nil,
		ede:       true,
	}, {
		req:       reqNoEDNS,
		sde:       agdtest.NewSDEConfig(false),
		name:      "unsupported_ede_no_sde",
		wantExtra: nil,
		ede:       true,
	}, {
		req:       reqNoEDNS,
		sde:       agdtest.NewSDEConfig(false),
		name:      "unsupported_no_ede",
		wantExtra: nil,
		ede:       false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
				Cloner:              agdtest.NewCloner(),
				BlockingMode:        &dnsmsg.BlockingModeNullIP{},
				StructuredErrors:    tc.sde,
				FilteredResponseTTL: agdtest.FilteredResponseTTL,
				EDEEnabled:          tc.ede,
			})
			require.NoError(t, err)

			resp, err := msgs.NewBlockedResp(tc.req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)
			assert.Equal(t, wantAns, resp.Answer)
			assert.Equal(t, tc.wantExtra, resp.Extra)
		})
	}
}

func TestConstructor_NewRespRCode(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)
	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	})

	for rcode, name := range dns.RcodeToString {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp := msgs.NewRespRCode(req, dnsmsg.RCode(rcode))
			require.NotNil(t, resp)
			require.Empty(t, resp.Answer)

			assert.Equal(t, rcode, resp.Rcode)

			require.Len(t, resp.Ns, 1)

			nsTTL := resp.Ns[0].Header().Ttl
			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), nsTTL)

			assert.Empty(t, resp.Extra)
		})
	}
}

func TestConstructor_NewRespTXT(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)

	req := dnsservertest.NewReq(testFQDN, dns.TypeTXT, dns.ClassINET, dnsservertest.SectionExtra{
		dnsservertest.NewOPT(true, dns.MaxMsgSize, &dns.EDNS0_EDE{}),
	})
	tooLong := strings.Repeat("1", dnsmsg.MaxTXTStringLen+1)

	testCases := []struct {
		name       string
		wantErrMsg string
		strs       []string
	}{{
		name:       "success",
		wantErrMsg: "",
		strs:       []string{"111"},
	}, {
		name:       "success_many",
		wantErrMsg: "",
		strs:       []string{"111", "222"},
	}, {
		name:       "success_nil",
		wantErrMsg: "",
		strs:       nil,
	}, {
		name:       "success_empty",
		wantErrMsg: "",
		strs:       []string{},
	}, {
		name:       "too_long",
		wantErrMsg: "txt string at index 0: too long: got 256 bytes, max 255",
		strs:       []string{tooLong},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, respErr := msgs.NewRespTXT(req, tc.strs...)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, respErr)

			if tc.wantErrMsg != "" {
				return
			}

			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			require.Len(t, resp.Answer, 1)

			ans := resp.Answer[0]
			txt := testutil.RequireTypeAssert[*dns.TXT](t, ans)

			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), txt.Hdr.Ttl)
			assert.Equal(t, tc.strs, txt.Txt)

			assert.Empty(t, resp.Extra)
		})
	}
}
