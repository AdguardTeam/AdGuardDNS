package filter_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashstorage"
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

	hashes, err := hashstorage.New(strings.Join(hosts, "\n"))
	require.NoError(t, err)

	ctx := context.Background()
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
		host: hashStrs[realisticHostIdx][:hashstorage.PrefixEncLen] + filter.GeneralTXTSuffix,
		wantHashStrs: []string{
			hashStrs[realisticHostIdx],
		},
		wantMatched: true,
	}, {
		name: "same_prefix",
		host: hashStrs[samePrefixHost1Idx][:hashstorage.PrefixEncLen] + filter.GeneralTXTSuffix,
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
