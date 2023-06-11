package hashprefix_test

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStorage_Hashes(t *testing.T) {
	s, err := hashprefix.NewStorage(testHost)
	require.NoError(t, err)

	h := sha256.Sum256([]byte(testHost))
	want := []string{hex.EncodeToString(h[:])}

	p := hashprefix.Prefix{h[0], h[1]}
	got := s.Hashes([]hashprefix.Prefix{p})
	assert.Equal(t, want, got)

	wrong := s.Hashes([]hashprefix.Prefix{{}})
	assert.Empty(t, wrong)
}

func TestStorage_Matches(t *testing.T) {
	s, err := hashprefix.NewStorage(testHost)
	require.NoError(t, err)

	got := s.Matches(testHost)
	assert.True(t, got)

	got = s.Matches(testOtherHost)
	assert.False(t, got)
}

func TestStorage_Reset(t *testing.T) {
	s, err := hashprefix.NewStorage(testHost)
	require.NoError(t, err)

	n, err := s.Reset(testOtherHost)
	require.NoError(t, err)

	assert.Equal(t, 1, n)

	h := sha256.Sum256([]byte(testOtherHost))
	want := []string{hex.EncodeToString(h[:])}

	p := hashprefix.Prefix{h[0], h[1]}
	got := s.Hashes([]hashprefix.Prefix{p})
	assert.Equal(t, want, got)

	prevHash := sha256.Sum256([]byte(testHost))
	prev := s.Hashes([]hashprefix.Prefix{{prevHash[0], prevHash[1]}})
	assert.Empty(t, prev)
}

// Sinks for benchmarks.
var (
	errSink  error
	strsSink []string
)

func BenchmarkStorage_Hashes(b *testing.B) {
	const N = 10_000

	var hosts []string
	for i := 0; i < N; i++ {
		hosts = append(hosts, fmt.Sprintf("%d."+testHost, i))
	}

	s, err := hashprefix.NewStorage(strings.Join(hosts, "\n"))
	require.NoError(b, err)

	var hashPrefixes []hashprefix.Prefix
	for i := 0; i < 4; i++ {
		hashPrefixes = append(hashPrefixes, hashprefix.Prefix{hosts[i][0], hosts[i][1]})
	}

	for n := 1; n <= 4; n++ {
		b.Run(strconv.FormatInt(int64(n), 10), func(b *testing.B) {
			hps := hashPrefixes[:n]

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				strsSink = s.Hashes(hps)
			}
		})
	}

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorage_Hashes/1-16            29928834                41.76 ns/op            0 B/op          0 allocs/op
	//	BenchmarkStorage_Hashes/2-16            18693033                63.80 ns/op            0 B/op          0 allocs/op
	//	BenchmarkStorage_Hashes/3-16            13492526                92.22 ns/op            0 B/op          0 allocs/op
	//	BenchmarkStorage_Hashes/4-16             9542425               109.2 ns/op             0 B/op          0 allocs/op
}

func BenchmarkStorage_ResetHosts(b *testing.B) {
	const N = 1_000

	var hosts []string
	for i := 0; i < N; i++ {
		hosts = append(hosts, fmt.Sprintf("%d."+testHost, i))
	}

	hostnames := strings.Join(hosts, "\n")
	s, err := hashprefix.NewStorage(hostnames)
	require.NoError(b, err)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, errSink = s.Reset(hostnames)
	}

	require.NoError(b, errSink)

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkStorage_ResetHosts-16              2212            469343 ns/op           36224 B/op       1002 allocs/op
}
