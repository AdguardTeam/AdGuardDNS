package filter_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSafeBrowsingServer(t *testing.T) {
	// Hashes

	const (
		realisticHostIdx = iota
		samePrefixHost1Idx
		samePrefixHost2Idx
	)

	hosts := []string{
		// Data closer to real world.
		realisticHostIdx: safeBrowsingHost,

		// Additional data that has the same prefixes.
		samePrefixHost1Idx: "3z",
		samePrefixHost2Idx: "7t",
	}

	hashStrs := make([]string, len(hosts))
	for i, h := range hosts {
		sum := sha256.Sum256([]byte(h))
		hashStrs[i] = hex.EncodeToString(sum[:])
	}

	// Hash Storage

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic("not implemented")
		},
	}

	cacheDir := t.TempDir()
	cachePath := filepath.Join(cacheDir, string(agd.FilterListIDSafeBrowsing))
	err := os.WriteFile(cachePath, []byte(strings.Join(hosts, "\n")), 0o644)
	require.NoError(t, err)

	hashes, err := filter.NewHashStorage(&filter.HashStorageConfig{
		URL:        &url.URL{},
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

	// Give the storage some time to process the hashes.
	//
	// TODO(a.garipov): Think of a less stupid way of doing this.
	time.Sleep(100 * time.Millisecond)

	testCases := []struct {
		name         string
		host         string
		wantHashStrs []string
		wantMatched  bool
	}{{
		name:         "nil",
		host:         "",
		wantHashStrs: nil,
		wantMatched:  false,
	}, {
		name: "realistic",
		host: hashStrs[realisticHostIdx][:filter.HashPrefixEncLen] + filter.GeneralTXTSuffix,
		wantHashStrs: []string{
			hashStrs[realisticHostIdx],
		},
		wantMatched: true,
	}, {
		name: "same_prefix",
		host: hashStrs[samePrefixHost1Idx][:filter.HashPrefixEncLen] + filter.GeneralTXTSuffix,
		wantHashStrs: []string{
			hashStrs[samePrefixHost1Idx],
			hashStrs[samePrefixHost2Idx],
		},
		wantMatched: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := filter.NewSafeBrowsingServer(hashes, nil)

			var gotHashStrs []string
			var matched bool
			gotHashStrs, matched, err = srv.Hashes(ctx, tc.host)
			require.NoError(t, err)

			assert.Equal(t, tc.wantMatched, matched)
			assert.ElementsMatch(t, tc.wantHashStrs, gotHashStrs)
		})
	}
}
