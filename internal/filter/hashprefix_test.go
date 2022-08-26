package filter_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_FilterFromContext_safeBrowsing(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, string(agd.FilterListIDSafeBrowsing))
	hosts := "scam.example.net\n"
	err := os.WriteFile(cachePath, []byte(hosts), 0o644)
	require.NoError(t, err)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic("not implemented")
		},
	}

	hashes, err := filter.NewHashStorage(&filter.HashStorageConfig{
		URL:        nil,
		ErrColl:    errColl,
		ID:         agd.FilterListIDSafeBrowsing,
		CachePath:  cachePath,
		RefreshIvl: testRefreshIvl,
	})
	require.NoError(t, err)

	ctx := context.Background()
	err = hashes.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return hashes.Shutdown(ctx)
	})

	// Fake Data

	onLookupIP := func(_ context.Context, network, _ string) (ips []net.IP, err error) {
		return []net.IP{safeBrowsingSafeIP4}, nil
	}

	fltsURL, svcsURL, ssURL, cacheDir := prepareIndex(t)
	c := &filter.DefaultStorageConfig{
		BlockedServiceIndexURL:    svcsURL,
		FilterIndexURL:            fltsURL,
		GeneralSafeSearchRulesURL: ssURL,
		YoutubeSafeSearchRulesURL: ssURL,
		SafeBrowsing: &filter.HashPrefixConfig{
			Hashes:          hashes,
			ReplacementHost: safeBrowsingSafeHost,
			CacheTTL:        10 * time.Second,
			CacheSize:       100,
		},
		AdultBlocking: &filter.HashPrefixConfig{},
		ErrColl:       errColl,
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
		ID:                  "default",
		RuleListIDs:         []agd.FilterListID{},
		ParentalEnabled:     true,
		SafeBrowsingEnabled: true,
	}

	// Test

	req := &dns.Msg{
		Question: []dns.Question{{
			Name:   safeBrowsingSubFQDN,
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}

	ri := newReqInfo(g, nil, safeBrowsingSubHost, clientIP, dns.TypeA)
	ctx = agd.ContextWithRequestInfo(ctx, ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

	var r filter.Result
	r, err = f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)
	require.IsType(t, (*filter.ResultModified)(nil), r)

	rm, _ := r.(*filter.ResultModified)
	assert.Equal(t, rm.Rule, agd.FilterRuleText(safeBrowsingHost))
	assert.Equal(t, rm.List, agd.FilterListIDSafeBrowsing)
}
