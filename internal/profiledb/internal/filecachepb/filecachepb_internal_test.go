package filecachepb

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// envVarName is the environment variable name the presence and value of which
// define whether to run the benchmarks with the data from the given file.
//
// The path should be an absolute path.
const envVarName = "ADGUARD_DNS_TEST_PROFILEDB_JSON"

// newCache is a helper that allows using a prepared JSON file for loading the
// data for benchmarks from the environment.
func newCache(tb testing.TB) (cache *internal.FileCache) {
	tb.Helper()

	filePath := os.Getenv(envVarName)
	if filePath == "" {
		prof, dev := profiledbtest.NewProfile(tb)
		cache = &internal.FileCache{
			SyncTime: time.Now().Round(0).UTC(),
			Profiles: []*agd.Profile{prof},
			Devices:  []*agd.Device{dev},
			Version:  internal.FileCacheVersion,
		}

		return cache
	}

	tb.Logf("using %q as source for profiledb data", filePath)

	data, err := os.ReadFile(filePath)
	require.NoError(tb, err)

	err = json.Unmarshal(data, cache)
	require.NoError(tb, err)

	return cache
}

func BenchmarkCache(b *testing.B) {
	cache := newCache(b)

	var err error
	var fileCache *FileCache

	b.Run("to_protobuf", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			fileCache = toProtobuf(cache)
		}

		require.NoError(b, err)
		require.NotEmpty(b, fileCache)
	})

	b.Run("from_protobuf", func(b *testing.B) {
		var gotCache *internal.FileCache

		b.ReportAllocs()
		for b.Loop() {
			gotCache, err = toInternal(
				fileCache,
				profiledbtest.Logger,
				profiledbtest.ProfileAccessConstructor,
				profiledbtest.RespSzEst,
			)
		}

		require.NoError(b, err)
		require.NotEmpty(b, gotCache)
	})

	var data []byte

	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			data, err = proto.Marshal(fileCache)
		}

		require.NoError(b, err)
		require.NotEmpty(b, data)
	})

	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			err = proto.Unmarshal(data, fileCache)
		}

		require.NoError(b, err)
		require.NotEmpty(b, fileCache)
	})

	// Most recent results:
	//
	// goos: linux
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb
	// cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	// BenchmarkCache/to_protobuf-16         	  274957	      5419 ns/op	    3000 B/op	      60 allocs/op
	// BenchmarkCache/from_protobuf-16       	   40694	     27856 ns/op	    9792 B/op	      70 allocs/op
	// BenchmarkCache/encode-16              	  171058	      6776 ns/op	     480 B/op	       1 allocs/op
	// BenchmarkCache/decode-16              	   72825	     14257 ns/op	    3016 B/op	      74 allocs/op
}
