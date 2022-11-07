package dnsmsg_test

import (
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

func TestConstructor_NewBlockedRespMsg(t *testing.T) {
	mc := dnsmsg.Constructor{
		FilteredResponseTTL: testFltRespTTL,
	}

	testCases := []struct {
		name       string
		wantAnsNum int
		qt         uint16
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
			req := dnsservertest.NewReq("example.com", tc.qt, dns.ClassINET)
			resp, err := mc.NewBlockedRespMsg(req)
			require.NoError(t, err)
			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			ttl := uint32(testFltRespTTL.Seconds())
			if tc.wantAnsNum == 0 {
				assert.Empty(t, resp.Answer)

				require.Len(t, resp.Ns, 1)

				ns := resp.Ns[0]
				assert.Equal(t, ttl, ns.Header().Ttl)
			} else {
				require.Len(t, resp.Answer, 1)

				ans := resp.Answer[0]
				assert.Equal(t, ttl, ans.Header().Ttl)
			}
		})
	}
}

func TestConstructor_noAnswerMethods(t *testing.T) {
	mc := dnsmsg.Constructor{
		FilteredResponseTTL: testFltRespTTL,
	}

	req := dnsservertest.NewReq("example.com", dns.TypeA, dns.ClassINET)
	ttl := uint32(testFltRespTTL.Seconds())

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

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := tc.method(req)
			require.NotNil(t, resp)
			require.Len(t, resp.Ns, 1)

			assert.Empty(t, resp.Answer)
			assert.Equal(t, tc.want, dnsmsg.RCode(resp.Rcode))

			ns := resp.Ns[0]
			assert.Equal(t, ttl, ns.Header().Ttl)
		})
	}
}

func TestConstructor_NewTXTRespMsg(t *testing.T) {
	mc := dnsmsg.Constructor{
		FilteredResponseTTL: testFltRespTTL,
	}

	req := dnsservertest.NewReq("example.com.", dns.TypeTXT, dns.ClassINET)
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
			resp, err := mc.NewTXTRespMsg(req, tc.strs...)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)

			if tc.wantErrMsg != "" {
				return
			}

			require.NotNil(t, resp)

			assert.Equal(t, dns.RcodeSuccess, resp.Rcode)

			require.Len(t, resp.Answer, 1)

			ans := resp.Answer[0]
			ttl := uint32(testFltRespTTL.Seconds())
			assert.Equal(t, ttl, ans.Header().Ttl)

			txt := ans.(*dns.TXT)
			assert.Equal(t, tc.strs, txt.Txt)
		})
	}
}

func TestConstructor_AppendDebugExtra(t *testing.T) {
	mc := dnsmsg.Constructor{
		FilteredResponseTTL: testFltRespTTL,
	}

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
		wantExtra:  newTXTExtra(uint32(mc.FilteredResponseTTL.Seconds()), shortText),
		wantErrMsg: "",
	}, {
		name: "long_text",
		text: longText,
		qt:   dns.TypeTXT,
		wantExtra: newTXTExtra(
			uint32(mc.FilteredResponseTTL.Seconds()),
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
		wantExtra:  newTXTExtra(uint32(mc.FilteredResponseTTL.Seconds()), ""),
		wantErrMsg: "",
	}}

	const fqdn = "example.com."

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
