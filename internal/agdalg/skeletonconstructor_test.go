package agdalg_test

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdalg"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
)

// testInitSize is the initial size for the buffers in the tests.
const testInitSize = 128

func TestSkeletonConstructor(t *testing.T) {
	t.Parallel()

	c := agdalg.NewSkeletonConstructor(testInitSize, testInitSize)

	testCases := []struct {
		name string
		in   string
		want string
	}{{
		name: "empty",
		in:   "",
		want: "",
	}, {
		name: "ascii",
		in:   "example",
		want: "exarnple",
	}, {
		name: "confusable",
		in:   "ｅxample",
		want: "exarnple",
	}, {
		name: "long",
		in:   strings.Repeat("𝕊", 4000),
		want: strings.Repeat("S", 4000),
	}, {
		name: "mixed_long",
		in:   strings.Repeat("𝕊S", 2000),
		want: strings.Repeat("SS", 2000),
	}, {
		name: "not_confusable",
		in:   "👍👍👍",
		want: "👍👍👍",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tc.want, c.Skeleton(tc.in))
		})
	}
}

// confusableCases is the set of cases for benchmarking and fuzzing
// [agdalg.SkeletonConstructor].
var confusableCases = []struct {
	name string
	in   string
	want string
}{{
	name: "empty",
	in:   "",
	want: "",
}, {
	name: "hostname_one_confusable",
	in:   "ｅxample.com",
	want: "exarnple.corn",
}, {
	name: "all_confusable",
	in:   "ｅｅｅｅ",
	want: "eeee",
}, {
	name: "all_confusable_ascii",
	in:   "mmmm",
	want: "rnrnrnrn",
}, {
	name: "mixed_confusable",
	in:   "𝕊s𝕊s𝕊s",
	want: "SsSsSs",
}, {
	name: "no_confusable_ascii",
	in:   "aaaa",
	want: "aaaa",
}, {
	name: "max_length_label",
	in:   strings.Repeat("a", netutil.MaxDomainLabelLen),
	want: strings.Repeat("a", netutil.MaxDomainLabelLen),
}}

func BenchmarkSkeletonConstructor_Skeleton(b *testing.B) {
	c := agdalg.NewSkeletonConstructor(testInitSize, testInitSize)

	for _, bc := range confusableCases {
		var got string

		b.Run(bc.name, func(b *testing.B) {
			// Warm up the internal pools.
			got = c.Skeleton(bc.in)

			b.ReportAllocs()
			for b.Loop() {
				got = c.Skeleton(bc.in)
			}
		})

		assert.Equal(b, bc.want, got)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdalg
	//	cpu: Apple M4 Pro
	//  BenchmarkSkeletonConstructor_Skeleton/empty-14                              21885146	       47.37 ns/op	       0 B/op          0 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/hostname_one_confusable-14         	 6473227	       186.2 ns/op	      16 B/op	       1 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/all_confusable-14                  	 6888572	       174.2 ns/op	       4 B/op	       1 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/all_confusable_ascii-14            	10908920	       111.9 ns/op	       8 B/op	       1 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/mixed_confusable-14                	 7063236	       170.0 ns/op	       8 B/op	       1 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/no_confusable_ascii-14             	11704665	       103.3 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkSkeletonConstructor_Skeleton/max_length_label-14                	 2213794	       545.4 ns/op	       0 B/op	       0 allocs/op
}

func FuzzSkeletonConstructor_Skeleton(f *testing.F) {
	for _, cc := range confusableCases {
		f.Add(cc.in)
	}

	c := agdalg.NewSkeletonConstructor(testInitSize, testInitSize)

	f.Fuzz(func(t *testing.T, in string) {
		assert.NotPanics(t, func() {
			_ = c.Skeleton(in)
		})
	})
}
