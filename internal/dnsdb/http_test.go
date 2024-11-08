package dnsdb_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_ServeHTTP(t *testing.T) {
	const domain = "domain.example"

	testIP := netip.MustParseAddr("1.2.3.4")

	successHdr := http.Header{
		httphdr.ContentType:     []string{agdhttp.HdrValTextCSV},
		httphdr.Trailer:         []string{httphdr.XError},
		httphdr.ContentEncoding: []string{agdhttp.HdrValGzip},
	}

	newMsg := func(rcode int, name string, qtype uint16) (m *dns.Msg) {
		return dnsservertest.NewResp(
			rcode,
			dnsservertest.NewReq(name, qtype, dns.ClassINET),
			dnsservertest.SectionAnswer{
				dnsservertest.NewA(domain, 0, testIP),
			},
		)
	}

	testCases := []struct {
		name     string
		msgs     []*dns.Msg
		wantHdr  http.Header
		wantResp [][]byte
	}{{
		name: "single",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, domain, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: [][]byte{[]byte(domain + `,A,NOERROR,` + testIP.String() + `,1`)},
	}, {
		name: "existing",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, domain, dns.TypeA),
			newMsg(dns.RcodeSuccess, domain, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: [][]byte{[]byte(domain + `,A,NOERROR,` + testIP.String() + `,2`)},
	}, {
		name: "different",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, domain, dns.TypeA),
			newMsg(dns.RcodeSuccess, "sub."+domain, dns.TypeA),
		},
		wantHdr: successHdr,
		wantResp: [][]byte{
			[]byte("sub." + domain + `,A,NOERROR,` + testIP.String() + `,1`),
			[]byte(domain + `,A,NOERROR,` + testIP.String() + `,1`),
		},
	}, {
		name: "non-recordable",
		msgs: []*dns.Msg{
			// Not NOERROR.
			newMsg(dns.RcodeBadName, domain, dns.TypeA),
			// Not A/AAAA.
			newMsg(dns.RcodeSuccess, domain, dns.TypeSRV),
			// Android metrics.
			newMsg(dns.RcodeSuccess, domain+"-dnsotls-ds.metric.gstatic.com.", dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: [][]byte{},
	}}

	record := func(
		t *testing.T,
		db dnsdb.Interface,
		msgs []*dns.Msg,
	) {
		t.Helper()

		for _, m := range msgs {
			ctx := context.Background()
			db.Record(ctx, m, &agd.RequestInfo{
				// Emulate the logic from init middleware.
				//
				// See [initial.Middleware.newRequestInfo].
				Host: strings.TrimSuffix(m.Question[0].Name, "."),
			})
		}
	}

	r := httptest.NewRequest(
		http.MethodGet,
		(&url.URL{
			Scheme: urlutil.SchemeHTTP,
			Host:   "dnsdb.example",
		}).String(),
		nil,
	)
	r.Header.Add(httphdr.AcceptEncoding, agdhttp.HdrValGzip)

	for _, tc := range testCases {
		db := dnsdb.New(&dnsdb.DefaultConfig{
			ErrColl: agdtest.NewErrorCollector(),
			MaxSize: 100,
		})
		rw := httptest.NewRecorder()

		t.Run(tc.name, func(t *testing.T) {
			record(t, db, tc.msgs)

			db.ServeHTTP(rw, r)
			require.Equal(t, http.StatusOK, rw.Code)

			assert.Equal(t, tc.wantHdr, rw.Header())

			gzipr, err := gzip.NewReader(rw.Body)
			require.NoError(t, err)

			var decResp []byte
			decResp, err = io.ReadAll(gzipr)
			require.NoError(t, err)

			lines := bytes.Split(decResp, []byte("\n"))
			assert.ElementsMatch(t, tc.wantResp, lines[:len(lines)-1])
		})
	}
}
