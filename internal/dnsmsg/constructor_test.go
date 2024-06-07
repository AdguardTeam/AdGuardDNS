package dnsmsg_test

import (
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTXTExtra is a helper constructor of the expected extra data.
func newTXTExtra(ttl uint32, strs ...string) (extra []dns.RR) {
	return []dns.RR{&dns.TXT{
		Hdr: dns.RR_Header{
			Rrtype: dns.TypeTXT,
			Class:  dns.ClassCHAOS,
			Ttl:    ttl,
		},
		Txt: strs,
	}}
}

func TestConstructor_NewBlockedRespMsg_nullIP(t *testing.T) {
	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)

	testCases := []struct {
		name       string
		wantAnsNum int
		qt         dnsmsg.RRType
	}{{
		name:       "a",
		wantAnsNum: 1,
		qt:         dns.TypeA,
	}, {
		name:       "aaaa",
		wantAnsNum: 1,
		qt:         dns.TypeAAAA,
	}, {
		name:       "txt",
		wantAnsNum: 0,
		qt:         dns.TypeTXT,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := dnsservertest.NewReq(testFQDN, tc.qt, dns.ClassINET)
			resp, err := mc.NewBlockedRespMsg(req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			const wantTTL = testFltRespTTLSec
			if tc.wantAnsNum == 0 {
				assert.Empty(t, resp.Answer)

				require.Len(t, resp.Ns, 1)

				nsTTL := resp.Ns[0].Header().Ttl
				assert.Equal(t, wantTTL, nsTTL)
			} else {
				require.Len(t, resp.Answer, 1)

				ansTTL := resp.Answer[0].Header().Ttl
				assert.Equal(t, wantTTL, ansTTL)
			}
		})
	}
}

func TestConstructor_NewBlockedRespMsg_customIP(t *testing.T) {
	testCases := []struct {
		messages *dnsmsg.Constructor
		name     string
		wantA    bool
		wantAAAA bool
	}{{
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
			IPv6: []netip.Addr{testIPv6},
		}, testFltRespTTL),
		name:     "both",
		wantA:    true,
		wantAAAA: true,
	}, {
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
		}, testFltRespTTL),
		name:     "ipv4_only",
		wantA:    true,
		wantAAAA: false,
	}, {
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeCustomIP{
			IPv6: []netip.Addr{testIPv6},
		}, testFltRespTTL),
		name:     "ipv6_only",
		wantA:    false,
		wantAAAA: true,
	}, {
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{},
			IPv6: []netip.Addr{},
		}, testFltRespTTL),
		name:     "empty",
		wantA:    false,
		wantAAAA: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqA := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)
			respA, err := tc.messages.NewBlockedRespMsg(reqA)
			require.NoError(t, err)
			require.NotNil(t, respA)

			assert.Equal(t, dns.RcodeSuccess, respA.Rcode)

			if tc.wantA {
				require.Len(t, respA.Answer, 1)

				a := testutil.RequireTypeAssert[*dns.A](t, respA.Answer[0])
				assert.Equal(t, net.IP(testIPv4.AsSlice()), a.A)
			} else {
				assert.Empty(t, respA.Answer)
			}

			reqAAAA := dnsservertest.NewReq(testFQDN, dns.TypeAAAA, dns.ClassINET)
			respAAAA, err := tc.messages.NewBlockedRespMsg(reqAAAA)
			require.NoError(t, err)
			require.NotNil(t, respAAAA)

			assert.Equal(t, dns.RcodeSuccess, respAAAA.Rcode)

			if tc.wantAAAA {
				require.Len(t, respAAAA.Answer, 1)

				aaaa := testutil.RequireTypeAssert[*dns.AAAA](t, respAAAA.Answer[0])
				assert.Equal(t, net.IP(testIPv6.AsSlice()), aaaa.AAAA)
			} else {
				assert.Empty(t, respAAAA.Answer)
			}
		})
	}
}

func TestConstructor_NewBlockedRespMsg_noAnswer(t *testing.T) {
	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)

	testCases := []struct {
		messages *dnsmsg.Constructor
		name     string
		rcode    dnsmsg.RCode
	}{{
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNXDOMAIN{}, testFltRespTTL),
		name:     "nxdomain",
		rcode:    dns.RcodeNameError,
	}, {
		messages: dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeREFUSED{}, testFltRespTTL),
		name:     "refused",
		rcode:    dns.RcodeRefused,
	}}

	const wantTTL = testFltRespTTLSec
	for _, tc := range testCases {
		resp, err := tc.messages.NewBlockedRespMsg(req)
		require.NoError(t, err)
		require.NotNil(t, resp)

		assert.Equal(t, tc.rcode, dnsmsg.RCode(resp.Rcode))
		assert.Empty(t, resp.Answer)

		require.Len(t, resp.Ns, 1)

		nsTTL := resp.Ns[0].Header().Ttl
		assert.Equal(t, wantTTL, nsTTL)
	}
}

func TestConstructor_noAnswerMethods(t *testing.T) {
	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)
	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)

	testCases := []struct {
		method func(req *dns.Msg) (resp *dns.Msg)
		name   string
		want   dnsmsg.RCode
	}{{
		method: mc.NewMsgFORMERR,
		name:   "formerr",
		want:   dns.RcodeFormatError,
	}, {
		method: mc.NewMsgNXDOMAIN,
		name:   "nxdomain",
		want:   dns.RcodeNameError,
	}, {
		method: mc.NewMsgREFUSED,
		name:   "refused",
		want:   dns.RcodeRefused,
	}, {
		method: mc.NewMsgSERVFAIL,
		name:   "servfail",
		want:   dns.RcodeServerFailure,
	}, {
		method: mc.NewMsgNODATA,
		name:   "nodata",
		want:   dns.RcodeSuccess,
	}}

	const wantTTL = testFltRespTTLSec
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.method(req)
			require.NotNil(t, resp)
			require.Len(t, resp.Ns, 1)

			assert.Empty(t, resp.Answer)
			assert.Equal(t, tc.want, dnsmsg.RCode(resp.Rcode))

			nsTTL := resp.Ns[0].Header().Ttl
			assert.Equal(t, wantTTL, nsTTL)
		})
	}
}

func TestConstructor_NewTXTRespMsg(t *testing.T) {
	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)
	req := dnsservertest.NewReq(testFQDN, dns.TypeTXT, dns.ClassINET)
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

	const wantTTL = testFltRespTTLSec
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := mc.NewTXTRespMsg(req, tc.strs...)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			if tc.wantErrMsg != "" {
				return
			}

			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			require.Len(t, resp.Answer, 1)

			ans := resp.Answer[0]
			ansTTL := ans.Header().Ttl
			assert.Equal(t, wantTTL, ansTTL)

			txt := testutil.RequireTypeAssert[*dns.TXT](t, ans)
			assert.Equal(t, tc.strs, txt.Txt)
		})
	}
}

func TestConstructor_AppendDebugExtra(t *testing.T) {
	mc := dnsmsg.NewConstructor(nil, &dnsmsg.BlockingModeNullIP{}, testFltRespTTL)
	shortText := "This is a short test text"
	longText := strings.Repeat("a", 2*dnsmsg.MaxTXTStringLen)

	testCases := []struct {
		name       string
		text       string
		wantErrMsg string
		wantExtra  []dns.RR
		qt         uint16
	}{{
		name:       "short_text",
		text:       shortText,
		qt:         dns.TypeTXT,
		wantExtra:  newTXTExtra(testFltRespTTLSec, shortText),
		wantErrMsg: "",
	}, {
		name: "long_text",
		text: longText,
		qt:   dns.TypeTXT,
		wantExtra: newTXTExtra(
			testFltRespTTLSec,
			longText[:dnsmsg.MaxTXTStringLen],
			longText[dnsmsg.MaxTXTStringLen:],
		),
		wantErrMsg: "",
	}, {
		name:       "error_type",
		text:       "Type A",
		qt:         dns.TypeA,
		wantExtra:  nil,
		wantErrMsg: "bad qtype for txt resp: A",
	}, {
		name:       "empty_text",
		text:       "",
		qt:         dns.TypeTXT,
		wantExtra:  newTXTExtra(testFltRespTTLSec, ""),
		wantErrMsg: "",
	}}

	const fqdn = testFQDN

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				MsgHdr: dns.MsgHdr{
					Id: dns.Id(),
				},
				Question: []dns.Question{{
					Name:   fqdn,
					Qtype:  tc.qt,
					Qclass: dns.ClassCHAOS,
				}},
			}

			resp := &dns.Msg{}
			resp = resp.SetReply(req)

			err := mc.AppendDebugExtra(req, resp, tc.text)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			wantExtra := tc.wantExtra
			if len(wantExtra) > 0 {
				wantExtra[0].Header().Name = fqdn
			}

			assert.Equal(t, resp.Extra, tc.wantExtra)
		})
	}
}
