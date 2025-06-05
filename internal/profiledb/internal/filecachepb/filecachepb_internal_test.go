package filecachepb

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

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
			gotCache, err = toInternal(fileCache, testLogger, profiledbtest.RespSzEst)
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
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkCache/to_protobuf-12         	  542451	      2133 ns/op	    2984 B/op	      59 allocs/op
	// BenchmarkCache/from_protobuf-12       	   23119	     54038 ns/op	    9400 B/op	      66 allocs/op
	// BenchmarkCache/encode-12              	  381763	      2982 ns/op	     480 B/op	       1 allocs/op
	// BenchmarkCache/decode-12              	  206245	      5791 ns/op	    2992 B/op	      74 allocs/op
}
