package consulkv_test

import (
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

	"github.com/AdguardTeam/AdGuardDNS/internal/agdhttp"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv/consulkv"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"
)

// testTimeout is the common timeout for tests and contexts.
const testTimeout = 1 * time.Second

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
	require.Equal(pt, key, db.sessionID)

	info, err := io.ReadAll(r.Body)
	require.NoError(pt, err)

	db.storage.Store(path.Base(r.URL.Path), info)
	rw.WriteHeader(http.StatusOK)
}

// get is used to handle GET HTTP method of accessing the database.
//
// See https://www.consul.io/api-docs#http-methods.
func (db *testKV) get(rw http.ResponseWriter, r *http.Request) {
	pt := testutil.PanicT{}

	_, key := path.Split(r.URL.Path)

	v, ok := db.storage.Load(key)
	if !ok {
		rw.WriteHeader(http.StatusNotFound)

		return
	}

	rw.WriteHeader(http.StatusOK)

	// TODO(a.garipov): Consider making testutil.RequireTypeAssert accept
	// testutil.PanicT.
	require.IsType(pt, ([]byte)(nil), v)

	val := v.([]byte)
	err := json.NewEncoder(rw).Encode([]*consulkv.KeyReadResponse{{
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
		default:
			panic(fmt.Errorf("unexpected method %q", r.Method))
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

func TestConsulKV(t *testing.T) {
	const (
		sessionID      = "sessionID"
		testKey        = "testKey"
		nonExistingKey = "nonExistingKey"
	)

	testVal := []byte("testVal")

	u, su := newKVServer(t, sessionID)
	kv, err := consulkv.NewKV(&consulkv.Config{
		URL:        u,
		SessionURL: su,
		Client: agdhttp.NewClient(&agdhttp.ClientConfig{
			Timeout: 15 * time.Second,
		}),
		Limiter:     rate.NewLimiter(rate.Limit(200)/60, 1),
		TTL:         time.Minute,
		MaxRespSize: datasize.MB * 1,
	})
	require.NoError(t, err)

	t.Run("set", func(t *testing.T) {
		err = kv.Set(testutil.ContextWithTimeout(t, testTimeout), testKey, testVal)
		require.NoError(t, err)
	})

	t.Run("hit", func(t *testing.T) {
		var val []byte
		var ok bool
		val, ok, err = kv.Get(testutil.ContextWithTimeout(t, testTimeout), testKey)
		require.NoError(t, err)

		assert.True(t, ok)
		assert.Equal(t, testVal, val)
	})

	t.Run("miss", func(t *testing.T) {
		var ok bool
		_, ok, err = kv.Get(testutil.ContextWithTimeout(t, testTimeout), nonExistingKey)
		require.NoError(t, err)

		assert.False(t, ok)
	})
}

func TestNewConsul(t *testing.T) {
	testCases := []struct {
		conf       *consulkv.Config
		name       string
		wantErrMsg string
	}{{
		conf: &consulkv.Config{
			URL:        &url.URL{Path: "kv/test"},
			SessionURL: &url.URL{},
		},
		name:       "correct",
		wantErrMsg: "",
	}, {
		conf:       &consulkv.Config{},
		name:       "nil_kv_url",
		wantErrMsg: "nil consul url",
	}, {
		conf: &consulkv.Config{
			URL:        &url.URL{Path: "kv"},
			SessionURL: &url.URL{},
		},
		name:       "few_parts",
		wantErrMsg: `consul url: path "kv": too few parts`,
	}, {
		conf: &consulkv.Config{
			URL:        &url.URL{Path: "kv/"},
			SessionURL: &url.URL{},
		},
		name:       "empty_last",
		wantErrMsg: `consul url: path "kv/": last part is empty`,
	}, {
		conf: &consulkv.Config{
			URL:        &url.URL{Path: "not-kv/test"},
			SessionURL: &url.URL{},
		},
		name:       "wrong_part",
		wantErrMsg: `consul url: path "not-kv/test": next to last part is "not-kv", want "kv"`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := consulkv.NewKV(tc.conf)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}
