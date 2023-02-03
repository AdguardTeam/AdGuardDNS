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
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashstorage"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_FilterFromContext_safeBrowsing(t *testing.T) {
	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, string(agd.FilterListIDSafeBrowsing))
	err := os.WriteFile(cachePath, []byte(safeBrowsingHost+"\n"), 0o644)
	require.NoError(t, err)

	hashes, err := hashstorage.New("")
	require.NoError(t, err)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic("not implemented")
		},
	}

	resolver := &agdtest.Resolver{
		OnLookupIP: func(
			_ context.Context,
			_ netutil.AddrFamily,
			_ string,
		) (ips []net.IP, err error) {
			return []net.IP{safeBrowsingSafeIP4}, nil
		},
	}

	c := prepareConf(t)

	c.SafeBrowsing, err = filter.NewHashPrefix(&filter.HashPrefixConfig{
		Hashes:          hashes,
		ErrColl:         errColl,
		Resolver:        resolver,
		ID:              agd.FilterListIDSafeBrowsing,
		CachePath:       cachePath,
		ReplacementHost: safeBrowsingSafeHost,
		Staleness:       1 * time.Hour,
		CacheTTL:        10 * time.Second,
		CacheSize:       100,
	})
	require.NoError(t, err)

	c.ErrColl = errColl
	c.Resolver = resolver

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
	ctx := agd.ContextWithRequestInfo(context.Background(), ri)

	f := s.FilterFromContext(ctx, ri)
	require.NotNil(t, f)
	testutil.CleanupAndRequireSuccess(t, f.Close)

	var r filter.Result
	r, err = f.FilterRequest(ctx, req, ri)
	require.NoError(t, err)

	rm := testutil.RequireTypeAssert[*filter.ResultModified](t, r)

	assert.Equal(t, rm.Rule, agd.FilterRuleText(safeBrowsingHost))
	assert.Equal(t, rm.List, agd.FilterListIDSafeBrowsing)
}
