package filter_test

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_FilterFromContext_safeSearch(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) { panic("not implemented") },
	}

	numLookupIP := 0
	onLookupIP := func(_ context.Context, network, _ string) (ips []net.IP, err error) {
		numLookupIP++

		if network == "ip4" {
			return []net.IP{safeSearchIPRespIP4}, nil
		}

		return []net.IP{safeSearchIPRespIP6}, nil
	}

	tmpFile, err := os.CreateTemp(t.TempDir(), "")
	require.NoError(t, err)

	_, err = tmpFile.Write([]byte("bad.example.com\n"))
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) { return os.Remove(tmpFile.Name()) })

	hashes, err := filter.NewHashStorage(&filter.HashStorageConfig{
		CachePath:  tmpFile.Name(),
		RefreshIvl: 1 * time.Hour,
	})
	require.NoError(t, err)

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(t)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing: &filter.HashPrefixConfig{
			Hashes: hashes,
		},
		AdultBlocking: &filter.HashPrefixConfig{
			Hashes: hashes,
		},
		ErrColl: errColl,
		Resolver: &agdtest.Resolver{
			OnLookupIP: onLookupIP,
		},
		CacheDir:              cacheDir,
		CustomFilterCacheSize: 100,
		SafeSearchCacheTTL:    10 * time.Second,
		RefreshIvl:            testRefreshIvl,
	}

	s, err := filter.NewDefaultStorage(c)
	require.NoError(t, err)

	g := &agd.FilteringGroup{
		ID:                "default",
		ParentalEnabled:   true,
		GeneralSafeSearch: true,
	}

	testCases := []struct {
		name        string
		host        string
		wantIP      net.IP
		rrtype      uint16
		wantLookups int
	}{{
		name:        "ip4",
		host:        safeSearchIPHost,
		wantIP:      safeSearchIPRespIP4,
		rrtype:      dns.TypeA,
		wantLookups: 0,
	}, {
		name:        "ip6",
		host:        safeSearchIPHost,
		wantIP:      nil,
		rrtype:      dns.TypeAAAA,
		wantLookups: 0,
	}, {
		name:        "host_ip4",
		host:        safeSearchHost,
		wantIP:      safeSearchIPRespIP4,
		rrtype:      dns.TypeA,
		wantLookups: 1,
	}, {
		name:        "host_ip6",
		host:        safeSearchHost,
		wantIP:      safeSearchIPRespIP6,
		rrtype:      dns.TypeAAAA,
		wantLookups: 1,
	}}

	for _, tc := range testCases {
		numLookupIP = 0
		req := dnsservertest.CreateMessage(tc.host, tc.rrtype)

		t.Run(tc.name, func(t *testing.T) {
			ri := newReqInfo(g, nil, tc.host, clientIP, tc.rrtype)
			ctx := agd.ContextWithRequestInfo(context.Background(), ri)

			f := s.FilterFromContext(ctx, ri)
			require.NotNil(t, f)
			testutil.CleanupAndRequireSuccess(t, f.Close)

			var r filter.Result
			r, err = f.FilterRequest(ctx, req, ri)
			require.NoError(t, err)

			assert.Equal(t, tc.wantLookups, numLookupIP)

			rm, ok := r.(*filter.ResultModified)
			require.True(t, ok)

			assert.Contains(t, rm.Rule, tc.host)
			assert.Equal(t, rm.List, agd.FilterListIDGeneralSafeSearch)

			res := rm.Msg
			require.NotNil(t, res)

			if tc.wantIP == nil {
				assert.Nil(t, res.Answer)

				return
			}

			require.Len(t, res.Answer, 1)

			switch tc.rrtype {
			case dns.TypeA:
				a, aok := res.Answer[0].(*dns.A)
				require.True(t, aok)

				assert.Equal(t, tc.wantIP, a.A)
			case dns.TypeAAAA:
				aaaa, aaaaok := res.Answer[0].(*dns.AAAA)
				require.True(t, aaaaok)

				assert.Equal(t, tc.wantIP, aaaa.AAAA)
			default:
				t.Fatalf("unexpected question type %d", tc.rrtype)
			}
		})
	}
}
