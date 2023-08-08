package safesearch_test

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/safesearch"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testSafeIPStr is the string representation of the IP address of the safe
// version of [testEngineWithIP].
const testSafeIPStr = "1.2.3.4"

// testIPOfEngineWithIP is the IP address of the safe version of
// search-engine-ip.example.
var testIPOfEngineWithIP net.IP = netip.MustParseAddr(testSafeIPStr).AsSlice()

// testIPOfEngineWithDomain is the IP address of the safe version of
// search-engine-domain.example.
var testIPOfEngineWithDomain = net.IP{1, 2, 3, 5}

// Common domain names for tests.
const (
	testOther            = "other.example"
	testEngineWithIP     = "search-engine-ip.example"
	testEngineWithDomain = "search-engine-domain.example"
	testSafeDomain       = "safe-search-engine-domain.example"
)

// testFilterRules is are common filtering rules for tests.
const testFilterRules = `|` + testEngineWithIP + `^$dnsrewrite=NOERROR;A;` + testSafeIPStr + "\n" +
	`|` + testEngineWithDomain + `^$dnsrewrite=NOERROR;CNAME;` + testSafeDomain

func TestFilter(t *testing.T) {
	reqCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, reqCh, testFilterRules, http.StatusOK)

	id, err := agd.NewFilterListID(filepath.Base(cachePath))
	require.NoError(t, err)

	f := safesearch.New(&safesearch.Config{
		Refreshable: &internal.RefreshableConfig{
			ID:        id,
			URL:       srvURL,
			CachePath: cachePath,
			Staleness: filtertest.Staleness,
			Timeout:   filtertest.Timeout,
			MaxSize:   filtertest.FilterMaxSize,
		},
		Resolver: &agdtest.Resolver{
			OnLookupIP: func(
				_ context.Context,
				_ netutil.AddrFamily,
				host string,
			) (ips []net.IP, err error) {
				switch host {
				case testSafeIPStr:
					return []net.IP{testIPOfEngineWithIP}, nil
				case testSafeDomain:
					return []net.IP{testIPOfEngineWithDomain}, nil
				default:
					return nil, errors.Error("test resolver error")
				}
			},
		},
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(ctx context.Context, err error) {
				panic("not implemented")
			},
		},
		CacheTTL:  1 * time.Minute,
		CacheSize: 100,
	})

	refrCtx, refrCancel := context.WithTimeout(context.Background(), filtertest.Timeout)
	t.Cleanup(refrCancel)

	err = f.Refresh(refrCtx, true)
	require.NoError(t, err)

	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	t.Run("no_match", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		req, ri := newReq(t, testOther, dns.TypeA)
		res, fltErr := f.FilterRequest(ctx, req, ri)
		require.NoError(t, fltErr)

		assert.Nil(t, res)

		t.Run("cached", func(t *testing.T) {
			res, fltErr = f.FilterRequest(ctx, req, ri)
			require.NoError(t, fltErr)

			// TODO(a.garipov): Find a way to make caches more inspectable.
			assert.Nil(t, res)
		})
	})

	t.Run("txt", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		req, ri := newReq(t, testEngineWithIP, dns.TypeTXT)
		res, fltErr := f.FilterRequest(ctx, req, ri)
		require.NoError(t, fltErr)

		assert.Nil(t, res)
	})

	t.Run("ip", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		req, ri := newReq(t, testEngineWithIP, dns.TypeA)
		res, fltErr := f.FilterRequest(ctx, req, ri)
		require.NoError(t, fltErr)

		rm := testutil.RequireTypeAssert[*internal.ResultModified](t, res)
		require.Len(t, rm.Msg.Answer, 1)

		assert.Equal(t, rm.Rule, agd.FilterRuleText(testEngineWithIP))

		a := testutil.RequireTypeAssert[*dns.A](t, rm.Msg.Answer[0])
		assert.Equal(t, testIPOfEngineWithIP, a.A)

		t.Run("cached", func(t *testing.T) {
			newReq, newRI := newReq(t, testEngineWithIP, dns.TypeA)

			var cachedRes internal.Result
			cachedRes, fltErr = f.FilterRequest(ctx, newReq, newRI)
			require.NoError(t, fltErr)

			// Do not assert that the results are the same, since a modified
			// result of a safe search is always cloned.  But assert that the
			// non-clonable fields are equal and that the message has reply
			// fields set properly.
			cachedRM := testutil.RequireTypeAssert[*internal.ResultModified](t, cachedRes)
			assert.NotSame(t, cachedRM, rm)
			assert.Equal(t, cachedRM.Msg.Id, newReq.Id)
			assert.Equal(t, cachedRM.List, rm.List)
			assert.Equal(t, cachedRM.Rule, rm.Rule)
		})
	})

	t.Run("domain", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), filtertest.Timeout)
		t.Cleanup(cancel)

		req, ri := newReq(t, testEngineWithDomain, dns.TypeA)
		res, fltErr := f.FilterRequest(ctx, req, ri)
		require.NoError(t, fltErr)

		rm := testutil.RequireTypeAssert[*internal.ResultModified](t, res)
		require.Len(t, rm.Msg.Answer, 1)

		assert.Equal(t, rm.Rule, agd.FilterRuleText(testEngineWithDomain))

		a := testutil.RequireTypeAssert[*dns.A](t, rm.Msg.Answer[0])
		assert.Equal(t, testIPOfEngineWithDomain, a.A)
	})
}

// newReq is a test helper that returns the DNS request and its accompanying
// request info with the given data.
func newReq(tb testing.TB, host string, qt dnsmsg.RRType) (req *dns.Msg, ri *agd.RequestInfo) {
	tb.Helper()

	req = dnsservertest.NewReq(host, qt, dns.ClassINET)
	ri = &agd.RequestInfo{
		Messages: agdtest.NewConstructor(),
		Host:     host,
		QType:    qt,
		QClass:   dns.ClassINET,
	}

	return req, ri
}
