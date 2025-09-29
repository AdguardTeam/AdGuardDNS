package hashprefix_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdurlflt"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_Hashes(t *testing.T) {
	s, err := hashprefix.NewStorage(testHashesData)
	require.NoError(t, err)

	h := sha256.Sum256([]byte(filtertest.HostAdultContent))
	want := []string{hex.EncodeToString(h[:])}

	p := hashprefix.Prefix{h[0], h[1]}
	got := s.Hashes([]hashprefix.Prefix{p})
	assert.Equal(t, want, got)

	wrong := s.Hashes([]hashprefix.Prefix{{}})
	assert.Empty(t, wrong)
}

func TestStorage_Matches(t *testing.T) {
	s, err := hashprefix.NewStorage(testHashesData)
	require.NoError(t, err)

	got := s.Matches(filtertest.HostAdultContent)
	assert.True(t, got)

	got = s.Matches(filtertest.Host)
	assert.False(t, got)
}

func TestStorage_Reset(t *testing.T) {
	s, err := hashprefix.NewStorage(testHashesData)
	require.NoError(t, err)

	assert.True(t, s.Matches(filtertest.HostAdultContent))

	newHashes := []byte(filtertest.Host + "\n")

	n, err := s.Reset(newHashes)
	require.NoError(t, err)

	assert.Equal(t, 1, n)
	assert.False(t, s.Matches(filtertest.HostAdultContent))

	h := sha256.Sum256([]byte(filtertest.Host))
	want := []string{hex.EncodeToString(h[:])}

	p := hashprefix.Prefix{h[0], h[1]}
	got := s.Hashes([]hashprefix.Prefix{p})
	assert.Equal(t, want, got)

	prevHash := sha256.Sum256([]byte(filtertest.HostAdultContent))
	prev := s.Hashes([]hashprefix.Prefix{{prevHash[0], prevHash[1]}})
	assert.Empty(t, prev)

	// Reset again to make sure that the reuse of the map did not affect the
	// results.
	n, err = s.Reset(newHashes)
	require.NoError(t, err)

	assert.Equal(t, 1, n)
	assert.False(t, s.Matches(filtertest.HostAdultContent))
	assert.True(t, s.Matches(filtertest.Host))
}

func BenchmarkStorage_Hashes(b *testing.B) {
	const N = 10_000

	var hosts []string
	for i := range N {
		hosts = append(hosts, fmt.Sprintf("%d."+filtertest.HostAdultContent, i))
	}

	s, err := hashprefix.NewStorage(agdurlflt.RulesToBytes(hosts))
	require.NoError(b, err)

	var hashPrefixes []hashprefix.Prefix
	for i := range 4 {
		hashPrefixes = append(hashPrefixes, hashprefix.Prefix{hosts[i][0], hosts[i][1]})
	}

	for n := 1; n <= 4; n++ {
		b.Run(strconv.FormatInt(int64(n), 10), func(b *testing.B) {
			hps := hashPrefixes[:n]
			var strs []string

			b.ReportAllocs()
			for b.Loop() {
				strs = s.Hashes(hps)
			}

			assert.NotEmpty(b, strs)
		})
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorage_Hashes/1-16      	 6934150	       174.6 ns/op	      80 B/op	       2 allocs/op
	//	BenchmarkStorage_Hashes/2-16      	 5912390	       203.5 ns/op	      80 B/op	       2 allocs/op
	//	BenchmarkStorage_Hashes/3-16      	 5288085	       225.6 ns/op	      80 B/op	       2 allocs/op
	//	BenchmarkStorage_Hashes/4-16      	 4613066	       259.9 ns/op	      80 B/op	       2 allocs/op
}

func BenchmarkStorage_ResetHosts(b *testing.B) {
	const N = 1_000

	var hosts []string
	for i := range N {
		hosts = append(hosts, fmt.Sprintf("%d."+filtertest.HostAdultContent, i))
	}

	hostnameData := agdurlflt.RulesToBytes(hosts)
	s, err := hashprefix.NewStorage(hostnameData)
	require.NoError(b, err)

	b.ReportAllocs()
	for b.Loop() {
		_, err = s.Reset(hostnameData)
	}

	require.NoError(b, err)

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorage_ResetHosts-16    	    6469	    186021 ns/op	  118392 B/op	    1009 allocs/op
}
