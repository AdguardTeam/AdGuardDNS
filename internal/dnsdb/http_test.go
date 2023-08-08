package dnsdb_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsdb"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/httphdr"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault_ServeHTTP(t *testing.T) {
	const dname = "some-domain.name"
	testIP := net.IP{1, 2, 3, 4}

	successHdr := http.Header{
		httphdr.ContentType:     []string{agdhttp.HdrValTextCSV},
		httphdr.Trailer:         []string{httphdr.XError},
		httphdr.ContentEncoding: []string{"gzip"},
	}

	newMsg := func(rcode int, name string, qtype uint16) (m *dns.Msg) {
		return dnsservertest.NewResp(
			rcode,
			dnsservertest.NewReq(name, qtype, dns.ClassINET),
			dnsservertest.SectionAnswer{
				dnsservertest.NewA(dname, 0, testIP),
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
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: [][]byte{[]byte(dname + `,A,NOERROR,` + testIP.String() + `,1`)},
	}, {
		name: "existing",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: [][]byte{[]byte(dname + `,A,NOERROR,` + testIP.String() + `,2`)},
	}, {
		name: "different",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
			newMsg(dns.RcodeSuccess, "sub."+dname, dns.TypeA),
		},
		wantHdr: successHdr,
		wantResp: [][]byte{
			[]byte("sub." + dname + `,A,NOERROR,` + testIP.String() + `,1`),
			[]byte(dname + `,A,NOERROR,` + testIP.String() + `,1`),
		},
	}, {
		name: "non-recordable",
		msgs: []*dns.Msg{
			// Not NOERROR.
			newMsg(dns.RcodeBadName, dname, dns.TypeA),
			// Not A/AAAA.
			newMsg(dns.RcodeSuccess, dname, dns.TypeSRV),
			// Android metrics.
			newMsg(dns.RcodeSuccess, dname+"-dnsotls-ds.metric.gstatic.com.", dns.TypeA),
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
				// See [dnssvc.initMw.newRequestInfo].
				Host: strings.TrimSuffix(m.Question[0].Name, "."),
			})
		}
	}

	r := httptest.NewRequest(
		http.MethodGet,
		(&url.URL{Scheme: "http", Host: "example.com"}).String(),
		nil,
	)
	r.Header.Add(httphdr.AcceptEncoding, "gzip")

	for _, tc := range testCases {
		db := dnsdb.New(&dnsdb.DefaultConfig{
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
			},
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
