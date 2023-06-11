package dnsdb_test

import (
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
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

// newTmpBolt creates a *dnsdb.Bolt with temporary DB file.
func newTmpBolt(t *testing.T) (db *dnsdb.Bolt) {
	tmpFile, err := os.CreateTemp(t.TempDir(), "*")
	require.NoError(t, err)

	conf := &dnsdb.BoltConfig{
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
		},
		Path: tmpFile.Name(),
	}

	return dnsdb.NewBolt(conf)
}

func TestBolt_ServeHTTP(t *testing.T) {
	const dname = "some-domain.name"

	successHdr := http.Header{
		httphdr.ContentType:     []string{agdhttp.HdrValTextCSV},
		httphdr.Trailer:         []string{httphdr.XError},
		httphdr.ContentEncoding: []string{"gzip"},
	}

	newMsg := func(rcode int, name string, qtype uint16) (m *dns.Msg) {
		return dnsservertest.NewResp(rcode, dnsservertest.NewReq(name, qtype, dns.ClassINET))
	}

	testCases := []struct {
		name     string
		msgs     []*dns.Msg
		wantHdr  http.Header
		wantResp []byte
	}{{
		name: "single",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: []byte(dname + `,A,NOERROR,,1` + "\n"),
	}, {
		name: "existing",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
		},
		wantHdr:  successHdr,
		wantResp: []byte(dname + `,A,NOERROR,,2` + "\n"),
	}, {
		name: "different",
		msgs: []*dns.Msg{
			newMsg(dns.RcodeSuccess, dname, dns.TypeA),
			newMsg(dns.RcodeSuccess, "sub."+dname, dns.TypeA),
		},
		wantHdr: successHdr,
		wantResp: []byte(dname + `,A,NOERROR,,1` + "\n" +
			"sub." + dname + `,A,NOERROR,,1` + "\n"),
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
		wantResp: []byte{},
	}}

	recordAndRefresh := func(
		t *testing.T,
		db interface {
			dnsdb.Interface
			agd.Refresher
		},
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

			err := db.Refresh(context.Background())
			require.NoError(t, err)
		}
	}

	r := httptest.NewRequest(
		http.MethodGet,
		(&url.URL{Scheme: "http", Host: "example.com"}).String(),
		nil,
	)
	r.Header.Add(httphdr.AcceptEncoding, "gzip")

	for _, tc := range testCases {
		db := newTmpBolt(t)
		rw := httptest.NewRecorder()

		t.Run(tc.name, func(t *testing.T) {
			recordAndRefresh(t, db, tc.msgs)

			db.ServeHTTP(rw, r)
			require.Equal(t, http.StatusOK, rw.Code)

			assert.Equal(t, tc.wantHdr, rw.Header())

			gzipr, err := gzip.NewReader(rw.Body)
			require.NoError(t, err)

			var decResp []byte
			decResp, err = io.ReadAll(gzipr)
			require.NoError(t, err)

			assert.Equal(t, tc.wantResp, decResp)
		})
	}

	t.Run("bad_db_path", func(t *testing.T) {
		db := dnsdb.NewBolt(&dnsdb.BoltConfig{
			Path: "bad/path",
			ErrColl: &agdtest.ErrorCollector{
				OnCollect: func(ctx context.Context, err error) { panic("not implemented") },
			},
		})

		w := httptest.NewRecorder()

		db.ServeHTTP(w, r)
		assert.Equal(
			t,
			"opening boltdb: opening file: open bad/path: no such file or directory\n",
			w.Body.String(),
		)
	})
}
