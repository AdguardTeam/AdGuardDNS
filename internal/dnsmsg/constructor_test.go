package dnsmsg_test

import (
	"net"
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

// newConstructor returns a new dnsmsg.Constructor with [testFltRespTTL].
func newConstructor(tb testing.TB) (c *dnsmsg.Constructor) {
	msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
		Cloner:              dnsmsg.NewCloner(dnsmsg.EmptyClonerStat{}),
		BlockingMode:        &dnsmsg.BlockingModeNullIP{},
		FilteredResponseTTL: agdtest.FilteredResponseTTL,
	})
	require.NoError(tb, err)

	return msgs
}

func TestConstructor_NewBlockedRespMsg_nullIP(t *testing.T) {
	t.Parallel()

	msgs := newConstructor(t)

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
			t.Parallel()

			req := dnsservertest.NewReq(testFQDN, tc.qt, dns.ClassINET)

			resp, respErr := msgs.NewBlockedRespMsg(req)
			require.NoError(t, respErr)
			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			if tc.wantAnsNum == 0 {
				assert.Empty(t, resp.Answer)

				require.Len(t, resp.Ns, 1)

				nsTTL := resp.Ns[0].Header().Ttl
				assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), nsTTL)
			} else {
				require.Len(t, resp.Answer, 1)

				ansTTL := resp.Answer[0].Header().Ttl
				assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), ansTTL)
			}
		})
	}
}

func TestConstructor_NewBlockedRespMsg_customIP(t *testing.T) {
	t.Parallel()

	cloner := agdtest.NewCloner()

	testCases := []struct {
		blockingMode dnsmsg.BlockingMode
		name         string
		wantA        bool
		wantAAAA     bool
	}{{
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
			IPv6: []netip.Addr{testIPv6},
		},
		name:     "both",
		wantA:    true,
		wantAAAA: true,
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{testIPv4},
		},
		name:     "ipv4_only",
		wantA:    true,
		wantAAAA: false,
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv6: []netip.Addr{testIPv6},
		},
		name:     "ipv6_only",
		wantA:    false,
		wantAAAA: true,
	}, {
		blockingMode: &dnsmsg.BlockingModeCustomIP{
			IPv4: []netip.Addr{},
			IPv6: []netip.Addr{},
		},
		name:     "empty",
		wantA:    false,
		wantAAAA: false,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			msgs, err := dnsmsg.NewConstructor(&dnsmsg.ConstructorConfig{
				Cloner:              cloner,
				BlockingMode:        tc.blockingMode,
				FilteredResponseTTL: agdtest.FilteredResponseTTL,
			})
			require.NoError(t, err)

			reqA := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)
			respA, err := msgs.NewBlockedRespMsg(reqA)
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
			respAAAA, err := msgs.NewBlockedRespMsg(reqAAAA)
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
	t.Parallel()

	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)
	cloner := agdtest.NewCloner()

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
				FilteredResponseTTL: agdtest.FilteredResponseTTL,
			})
			require.NoError(t, err)

			resp, err := msgs.NewBlockedRespMsg(req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, tc.rcode, dnsmsg.RCode(resp.Rcode))
			assert.Empty(t, resp.Answer)

			require.Len(t, resp.Ns, 1)

			nsTTL := resp.Ns[0].Header().Ttl
			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), nsTTL)
		})
	}
}

func TestConstructor_noAnswerMethods(t *testing.T) {
	t.Parallel()

	msgs := newConstructor(t)

	req := dnsservertest.NewReq(testFQDN, dns.TypeA, dns.ClassINET)

	testCases := []struct {
		method func(req *dns.Msg) (resp *dns.Msg)
		name   string
		want   dnsmsg.RCode
	}{{
		method: msgs.NewMsgFORMERR,
		name:   "formerr",
		want:   dns.RcodeFormatError,
	}, {
		method: msgs.NewMsgNXDOMAIN,
		name:   "nxdomain",
		want:   dns.RcodeNameError,
	}, {
		method: msgs.NewMsgREFUSED,
		name:   "refused",
		want:   dns.RcodeRefused,
	}, {
		method: msgs.NewMsgSERVFAIL,
		name:   "servfail",
		want:   dns.RcodeServerFailure,
	}, {
		method: msgs.NewMsgNODATA,
		name:   "nodata",
		want:   dns.RcodeSuccess,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := tc.method(req)
			require.NotNil(t, resp)
			require.Len(t, resp.Ns, 1)

			assert.Empty(t, resp.Answer)
			assert.Equal(t, tc.want, dnsmsg.RCode(resp.Rcode))

			nsTTL := resp.Ns[0].Header().Ttl
			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), nsTTL)
		})
	}
}

func TestConstructor_NewTXTRespMsg(t *testing.T) {
	t.Parallel()

	msgs := newConstructor(t)

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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, respErr := msgs.NewTXTRespMsg(req, tc.strs...)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, respErr)

			if tc.wantErrMsg != "" {
				return
			}

			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			require.Len(t, resp.Answer, 1)

			ans := resp.Answer[0]
			ansTTL := ans.Header().Ttl
			assert.Equal(t, uint32(agdtest.FilteredResponseTTLSec), ansTTL)

			txt := testutil.RequireTypeAssert[*dns.TXT](t, ans)
			assert.Equal(t, tc.strs, txt.Txt)
		})
	}
}

func TestConstructor_AppendDebugExtra(t *testing.T) {
	t.Parallel()

	msgs := newConstructor(t)

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
		wantExtra:  newTXTExtra(agdtest.FilteredResponseTTLSec, shortText),
		wantErrMsg: "",
	}, {
		name: "long_text",
		text: longText,
		qt:   dns.TypeTXT,
		wantExtra: newTXTExtra(
			agdtest.FilteredResponseTTLSec,
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
		wantExtra:  newTXTExtra(agdtest.FilteredResponseTTLSec, ""),
		wantErrMsg: "",
	}}

	const fqdn = testFQDN

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

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

			appendErr := msgs.AppendDebugExtra(req, resp, tc.text)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, appendErr)

			wantExtra := tc.wantExtra
			if len(wantExtra) > 0 {
				wantExtra[0].Header().Name = fqdn
			}

			assert.Equal(t, resp.Extra, tc.wantExtra)
		})
	}
}
