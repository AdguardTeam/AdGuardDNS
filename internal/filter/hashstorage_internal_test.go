package filter

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

var strsSink []string

func BenchmarkHashStorage_Hashes(b *testing.B) {
	const N = 10_000

	var hosts []string
	for i := 0; i < N; i++ {
		hosts = append(hosts, fmt.Sprintf("%d.porn.example.com", i))
	}

	// Don't use a constructor, since we don't need the whole contents of the
	// storage.
	//
	// TODO(a.garipov): Think of a better way to do this.
	hs := &HashStorage{
		mu:           &sync.RWMutex{},
		hashSuffixes: map[hashPrefix][]hashSuffix{},
		refr:         &refreshableFilter{id: "test_filter"},
	}

	err := hs.resetHosts(strings.Join(hosts, "\n"))
	require.NoError(b, err)

	var hashPrefixes []hashPrefix
	for i := 0; i < 4; i++ {
		hashPrefixes = append(hashPrefixes, hashPrefix{hosts[i][0], hosts[i][1]})
	}

	for n := 1; n <= 4; n++ {
		b.Run(strconv.FormatInt(int64(n), 10), func(b *testing.B) {
			hps := hashPrefixes[:n]

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				strsSink = hs.hashes(hps)
			}
		})
	}
}
