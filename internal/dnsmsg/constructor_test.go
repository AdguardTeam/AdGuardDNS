package dnsmsg_test

import (
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
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

func TestNewConstructor(t *testing.T) {
	t.Parallel()

	cloner := agdtest.NewCloner()
	badContactURL := errors.Must(url.Parse("invalid-scheme://devteam@adguard.com"))

	testCases := []struct {
		name       string
		conf       *dnsmsg.ConstructorConfig
		wantErrMsg string
	}{{
		name: "good",
		conf: &dnsmsg.ConstructorConfig{
			Cloner:              cloner,
			StructuredErrors:    agdtest.NewSDEConfig(true),
			BlockingMode:        &dnsmsg.BlockingModeNullIP{},
			FilteredResponseTTL: agdtest.FilteredResponseTTL,
			EDEEnabled:          true,
		},
		wantErrMsg: "",
	}, {
		name: "all_bad",
		conf: &dnsmsg.ConstructorConfig{
			FilteredResponseTTL: -1,
		},
		wantErrMsg: "configuration: " +
			"cloner: no value\n" +
			"structured errors: no value\n" +
			"blocking mode: no value\n" +
			"filtered response ttl: negative value",
	}, {
		name: "sde_enabled",
		conf: &dnsmsg.ConstructorConfig{
			Cloner:              cloner,
			StructuredErrors:    agdtest.NewSDEConfig(true),
			BlockingMode:        &dnsmsg.BlockingModeNullIP{},
			FilteredResponseTTL: agdtest.FilteredResponseTTL,
			EDEEnabled:          false,
		},
		wantErrMsg: "configuration: structured errors: " +
			"ede must be enabled to enable sde",
	}, {
		name: "sde_empty",
		conf: &dnsmsg.ConstructorConfig{
			Cloner: cloner,
			StructuredErrors: &dnsmsg.StructuredDNSErrorsConfig{
				Enabled: true,
			},
			BlockingMode:        &dnsmsg.BlockingModeNullIP{},
			FilteredResponseTTL: agdtest.FilteredResponseTTL,
			EDEEnabled:          true,
		},
		wantErrMsg: "configuration: structured errors: " +
			"contact data: empty value\n" +
			"justification: empty value",
	}, {
		name: "sde_bad",
		conf: &dnsmsg.ConstructorConfig{
			Cloner: cloner,
			StructuredErrors: &dnsmsg.StructuredDNSErrorsConfig{
				Enabled:       true,
				Contact:       []*url.URL{badContactURL, nil},
				Justification: "\uFFFE",
				Organization:  "\uFFFE",
			},
			BlockingMode:        &dnsmsg.BlockingModeNullIP{},
			FilteredResponseTTL: agdtest.FilteredResponseTTL,
			EDEEnabled:          true,
		},
		wantErrMsg: "configuration: structured errors: " +
			`contact data: at index 0: scheme: bad enum value: "invalid-scheme"` + "\n" +
			"contact data: at index 1: no value\n" +
			"justification: bad code point at index 0\n" +
			"organization: bad code point at index 0",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := dnsmsg.NewConstructor(tc.conf)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestConstructor_AppendDebugExtra(t *testing.T) {
	t.Parallel()

	msgs := agdtest.NewConstructor(t)

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

			assert.Equal(t, tc.wantExtra, resp.Extra)
		})
	}
}

// errSink is a sink for benchmark results.
var errSink error

func BenchmarkConstructor_AppendDebugExtra(b *testing.B) {
	msgs := agdtest.NewConstructor(b)

	longText := strings.Repeat("abc", 2*dnsmsg.MaxTXTStringLen)

	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Question: []dns.Question{{
			Name:   testFQDN,
			Qtype:  dns.TypeTXT,
			Qclass: dns.ClassCHAOS,
		}},
	}

	resp := &dns.Msg{}
	resp = resp.SetReply(req)

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		errSink = msgs.AppendDebugExtra(req, resp, longText)
	}

	assert.NoError(b, errSink)

	// Most recent results:
	//
	// goos: darwin
	// goarch: arm64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg
	// cpu: Apple M1 Pro
	// BenchmarkConstructor_AppendDebugExtra-8   	 8809124	       137.3 ns/op	     253 B/op	       2 allocs/op
}
