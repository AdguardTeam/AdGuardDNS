package agdalg

import (
	"strings"
	"testing"

	"github.com/AdguardTeam/golibs/netutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/text/transform"
)

func TestConfusablePrototyper(t *testing.T) {
	t.Parallel()

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
	}, {
		name: "err_short_src",
		in:   strings.Repeat("\xff", 5000),
		want: strings.Repeat("\xff", 5000),
	}, {
		name: "invalid_utf8",
		in:   string([]byte{0xc0, 0xc1, 0xfd}),
		want: string([]byte{0xc0, 0xc1, 0xfd}),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, n, err := transform.String(confusablePrototyper, tc.in)
			require.NoError(t, err)

			assert.Equal(t, len(tc.in), n)
			assert.Equal(t, tc.want, got)
		})
	}
}

// confusableCases is the set of cases for benchmarking [runePrototyper].
var confusableCases = []struct {
	name string
	in   string
	want string
}{{
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

func BenchmarkRunePrototyper_Transform(b *testing.B) {
	bufOut := make([]byte, netutil.MaxDomainNameLen)

	for _, bc := range confusableCases {
		src := []byte(bc.in)

		var (
			nDst int
			nSrc int
			err  error
		)

		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				nDst, nSrc, err = confusablePrototyper.Transform(bufOut, src, true)
			}
		})

		require.NoError(b, err)

		assert.Equal(b, len(src), nSrc)
		assert.Equal(b, bc.want, string(bufOut[:nDst]))
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdalg
	//	cpu: Apple M4 Pro
	//	BenchmarkRunePrototyper_Transform/hostname_one_confusable-14         	26691942	        44.92 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRunePrototyper_Transform/all_confusable-14                  	52138776	        23.19 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRunePrototyper_Transform/all_confusable_ascii-14            	75863343	        16.16 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRunePrototyper_Transform/mixed_confusable-14                	40583500	        28.57 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRunePrototyper_Transform/no_confusable_ascii-14             	75182670	        16.68 ns/op	       0 B/op	       0 allocs/op
	//	BenchmarkRunePrototyper_Transform/max_length_label-14                	 5202475	       225.6 ns/op	       0 B/op	       0 allocs/op
}
