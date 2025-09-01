package hashprefix_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// type check
//
// TODO(a.garipov): Move this into the actual package instead of keeping it in
// the test package if [filter.Storage] is moved.
var _ filter.HashMatcher = (*hashprefix.Matcher)(nil)

func TestMatcher(t *testing.T) {
	const (
		realisticHostIdx = iota
		samePrefixHost1Idx
		samePrefixHost2Idx
	)

	const suffix = filter.GeneralTXTSuffix

	hosts := []string{
		// Data closer to real world.
		realisticHostIdx: "scam.example.net",

		// Additional data that has the same prefixes.
		samePrefixHost1Idx: "3z",
		samePrefixHost2Idx: "7t",
	}

	hashStrs := make([]string, len(hosts))
	for i, h := range hosts {
		sum := sha256.Sum256([]byte(h))
		hashStrs[i] = hex.EncodeToString(sum[:])
	}

	hashes, err := hashprefix.NewStorage(agdurlflt.RulesToBytes(hosts))
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
		host: hashStrs[realisticHostIdx][:hashprefix.PrefixEncLen] + suffix,
		wantHashStrs: []string{
			hashStrs[realisticHostIdx],
		},
		wantMatched: true,
	}, {
		name: "same_prefix",
		host: hashStrs[samePrefixHost1Idx][:hashprefix.PrefixEncLen] + suffix,
		wantHashStrs: []string{
			hashStrs[samePrefixHost1Idx],
			hashStrs[samePrefixHost2Idx],
		},
		wantMatched: true,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := hashprefix.NewMatcher(map[string]*hashprefix.Storage{
				suffix: hashes,
			})

			var gotHashStrs []string
			var matched bool
			gotHashStrs, matched, err = srv.MatchByPrefix(ctx, tc.host)
			require.NoError(t, err)

			assert.Equal(t, tc.wantMatched, matched)
			assert.ElementsMatch(t, tc.wantHashStrs, gotHashStrs)
		})
	}
}
