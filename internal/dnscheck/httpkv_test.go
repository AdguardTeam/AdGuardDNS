package dnscheck_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testKV is a stub Consul KV DB for tests.
type testKV struct {
	storage   sync.Map
	sessionID string
}

const (
	sessPath = "/session/create"
	kvPath   = "/kv/test"
)

// put is used to handle PUT HTTP method of accessing the database.
//
// See https://www.consul.io/api-docs#http-methods.
func (db *testKV) put(rw http.ResponseWriter, r *http.Request) {
	pt := testutil.PanicT{}

	key := r.URL.Query().Get("acquire")
	require.NotEmpty(pt, key)

	info, err := io.ReadAll(r.Body)
	require.NoError(pt, err)

	db.storage.Store(key, info)
	rw.WriteHeader(http.StatusOK)
}

// get is used to handle GET HTTP method of accessing the database.
//
// See https://www.consul.io/api-docs#http-methods.
func (db *testKV) get(rw http.ResponseWriter, r *http.Request) {
	pt := testutil.PanicT{}

	_, key := path.Split(r.URL.Path)

	rw.WriteHeader(http.StatusOK)

	v, ok := db.storage.Load(key)
	if !ok {
		err := json.NewEncoder(rw).Encode([]struct{}{})
		require.NoError(pt, err)

		return
	}

	// TODO(a.garipov): Consider making testutil.RequireTypeAssert accept
	// testutil.PanicT.
	require.IsType(pt, ([]byte)(nil), v)

	val := v.([]byte)
	err := json.NewEncoder(rw).Encode([]struct {
		Value []byte `json:"Value"`
	}{{
		Value: val,
	}})
	require.NoError(pt, err)
}

// session is used to handle PUT HTTP method of creating the session.
//
// See https://www.consul.io/api-docs/session#create-session.
func (db *testKV) session(rw http.ResponseWriter, r *http.Request) {
	pt := testutil.PanicT{}

	require.Equal(pt, http.MethodPut, r.Method)

	err := json.NewEncoder(rw).Encode(struct {
		ID string `json:"ID"`
	}{
		ID: db.sessionID,
	})
	require.NoError(pt, err)
}

// ServeHTTP implements the http.Handler interface for *testKV.
func (db *testKV) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if p := r.URL.Path; p == sessPath {
		db.session(rw, r)
	} else if strings.HasPrefix(p, kvPath) {
		switch r.Method {
		case http.MethodPut:
			db.put(rw, r)
		case http.MethodGet:
			db.get(rw, r)
		}
	} else {
		panic(fmt.Errorf("unexpected path %q", p))
	}
}

// newKVServer returns URLs emulating behavior of Consul KV database server.
func newKVServer(t *testing.T, sessionID string) (kv, sess *url.URL) {
	db := &testKV{
		storage:   sync.Map{},
		sessionID: sessionID,
	}

	srv := httptest.NewServer(db)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	return u.JoinPath(kvPath), u.JoinPath(sessPath)
}

func TestHTTPKV(t *testing.T) {
	const (
		randomid    = "randomid"
		localDomain = "example.local"
	)

	conf := &dnscheck.ConsulConfig{
		Messages: &dnsmsg.Constructor{},
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, _ error) {},
		},
		Domains:      []string{localDomain},
		NodeLocation: "some-node-location",
		NodeName:     "some-node-name",
		TTL:          1 * time.Minute,
	}
	conf.ConsulKVURL, conf.ConsulSessionURL = newKVServer(t, randomid)
	dnsCk, err := dnscheck.NewConsul(conf)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
		Proto: agd.ProtoDNS,
	})

	req := dnsservertest.CreateMessage(randomid+"-"+localDomain, dns.TypeA)
	ri := &agd.RequestInfo{
		Device:      &agd.Device{ID: "some-device-id"},
		Profile:     &agd.Profile{ID: "some-profile-id"},
		ServerGroup: "some-server-group-name",
		Server:      "some-server-name",
		Host:        randomid + "-" + localDomain,
		RemoteIP:    testRemoteIP,
		QType:       dns.TypeA,
	}

	_, err = dnsCk.Check(ctx, req, ri)
	require.NoError(t, err)
	dnscheck.FlushConsulCache(t, dnsCk)

	t.Run("hit", func(t *testing.T) {
		wantResp := jobj{
			"device_id":         "some-device-id",
			"profile_id":        "some-profile-id",
			"server_group_name": "some-server-group-name",
			"server_name":       "some-server-name",
			"protocol":          agd.ProtoDNS.String(),
			"node_location":     "some-node-location",
			"node_name":         "some-node-name",
			"client_ip":         "1.2.3.4",
		}

		r := httptest.NewRequest(http.MethodGet, (&url.URL{
			Scheme: "http",
			Host:   randomid + "-" + localDomain,
			Path:   "/dnscheck/test",
		}).String(), strings.NewReader(""))
		rw := httptest.NewRecorder()

		dnsCk.ServeHTTP(rw, r)
		assert.Equal(t, http.StatusOK, rw.Code)

		body := jobj{}
		require.NoError(t, json.Unmarshal(rw.Body.Bytes(), &body))

		assert.Equal(t, wantResp, body)
	})

	t.Run("miss", func(t *testing.T) {
		const wantResp = `getting from consul: server "": ` +
			`response for key "nonrandomid" from consul has no items` + "\n"

		r := httptest.NewRequest(http.MethodGet, (&url.URL{
			Scheme: "http",
			Host:   "non" + randomid + "-" + localDomain,
			Path:   "/dnscheck/test",
		}).String(), strings.NewReader(""))
		rw := httptest.NewRecorder()

		dnsCk.ServeHTTP(rw, r)
		assert.Equal(t, http.StatusInternalServerError, rw.Code)

		assert.Equal(t, wantResp, rw.Body.String())
	})
}
