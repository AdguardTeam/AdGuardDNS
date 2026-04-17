package agdalg_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdalg"
	"github.com/masatana/go-textdistance"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testStr1 = "kitten"
	testStr2 = "sitting"

	testStrContains1 = "hub"
	testStrContains2 = "github.com"

	testStrTranspose1 = "label"
	testStrTranspose2 = "lable"

	testStrLong1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testStrLong2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestDamerauLevenshteinCalculator_Distance(t *testing.T) {
	c := agdalg.NewDamerauLevenshteinCalculator(0)

	testCases := []struct {
		a    string
		b    string
		name string
		want uint
	}{{
		a:    "",
		b:    "",
		name: "empty",
		want: 0,
	}, {
		a:    testStr1,
		b:    "",
		name: "all",
		want: uint(len(testStr1)),
	}, {
		a:    "",
		b:    testStr1,
		name: "all_reorder",
		want: uint(len(testStr1)),
	}, {
		a:    testStr1,
		b:    testStr2,
		name: "some",
		want: 3,
	}, {
		a:    testStrContains1,
		b:    testStrContains2,
		name: "contains",
		want: 7,
	}, {
		a:    testStrContains2,
		b:    testStrContains1,
		name: "contains_reorder",
		want: 7,
	}, {
		a:    testStrTranspose1,
		b:    testStrTranspose2,
		name: "transpose",
		want: 1,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := c.Distance(tc.a, tc.b)
			assert.Equal(t, tc.want, got)
		})
	}
}

func BenchmarkDamerauLevenshteinCalculator_Distance(b *testing.B) {
	c := agdalg.NewDamerauLevenshteinCalculator(0)

	// Warmup to fill the pool.
	_ = c.Distance(testStrLong1, testStrLong2)

	testCases := []struct {
		a    string
		b    string
		name string
		want uint
	}{{
		a:    testStrLong1,
		b:    "",
		name: "all",
		want: uint(len(testStrLong1)),
	}, {
		a:    testStrLong1,
		b:    testStrLong1,
		name: "same",
		want: 0,
	}, {
		a:    testStr1,
		b:    testStr2,
		name: "some",
		want: 3,
	}, {
		a:    testStr1,
		b:    testStrLong1,
		name: "length_diff",
		want: 63,
	}}

	for _, bc := range testCases {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				got := c.Distance(bc.a, bc.b)
				require.Equal(b, bc.want, got)
			}
		})
	}

	// Most recent results:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdalg
	//	cpu: AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
	//	BenchmarkDamerauLevenshteinCalculator_Distance/all-24         	 6300003	       191.0 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDamerauLevenshteinCalculator_Distance/same-24        	 6026179	       192.7 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDamerauLevenshteinCalculator_Distance/some-24        	 3828691	       310.8 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkDamerauLevenshteinCalculator_Distance/length_diff-24 	 1392019	       862.6 ns/op	       0 B/op	       0 allocs/op
}

func FuzzDamerauLevenshteinCalculator_Distance(f *testing.F) {
	c := agdalg.NewDamerauLevenshteinCalculator(0)

	f.Fuzz(func(t *testing.T, a, b string) {
		// Compare against another implementation, but only if both strings are
		// ASCII.
		if !isASCII(a) || !isASCII(b) {
			return
		}

		want := textdistance.DamerauLevenshteinDistance(a, b)
		got := c.Distance(a, b)
		require.Equal(t, uint(want), got)
	})
}

// isASCII returns true if s contains only printable ASCII characters.
func isASCII(s string) (ok bool) {
	for i := range s {
		if s[i] < ' ' || s[i] > '~' {
			return false
		}
	}

	return true
}
