package filecachepb

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Sinks for benchmarks
var (
	bytesSink     []byte
	cacheSink     = &internal.FileCache{}
	errSink       error
	fileCacheSink = &FileCache{}
)

// envVarName is the environment variable name the presence and value of which
// define whether to run the benchmarks with the data from the given file.
//
// The path should be an absolute path.
const envVarName = "ADGUARD_DNS_TEST_PROFILEDB_JSON"

// setCacheSink is a helper that allows using a prepared JSON file for loading
// the data for benchmarks from the environment.
func setCacheSink(tb testing.TB) {
	tb.Helper()

	filePath := os.Getenv(envVarName)
	if filePath == "" {
		prof, dev := profiledbtest.NewProfile(tb)
		cacheSink = &internal.FileCache{
			SyncTime: time.Now().Round(0).UTC(),
			Profiles: []*agd.Profile{prof},
			Devices:  []*agd.Device{dev},
			Version:  internal.FileCacheVersion,
		}

		return
	}

	tb.Logf("using %q as source for profiledb data", filePath)

	data, err := os.ReadFile(filePath)
	require.NoError(tb, err)

	err = json.Unmarshal(data, cacheSink)
	require.NoError(tb, err)
}

func BenchmarkCache(b *testing.B) {
	setCacheSink(b)

	b.Run("to_protobuf", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			fileCacheSink = toProtobuf(cacheSink)
		}

		require.NoError(b, errSink)
		require.NotEmpty(b, fileCacheSink)
	})

	b.Run("from_protobuf", func(b *testing.B) {
		var gotCache *internal.FileCache

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			gotCache, errSink = toInternal(fileCacheSink)
		}

		require.NoError(b, errSink)
		require.NotEmpty(b, gotCache)
	})

	b.Run("encode", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			bytesSink, errSink = proto.Marshal(fileCacheSink)
		}

		require.NoError(b, errSink)
		require.NotEmpty(b, bytesSink)
	})

	b.Run("decode", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			errSink = proto.Unmarshal(bytesSink, fileCacheSink)
		}

		require.NoError(b, errSink)
		require.NotEmpty(b, fileCacheSink)
	})

	// Most recent result, on a ThinkPad X13 with a Ryzen Pro 7 CPU:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/filecachepb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkCache/to_protobuf-16             674397              1657 ns/op            1240 B/op       22 allocs/op
	//	BenchmarkCache/from_protobuf-16            83577             14285 ns/op            7400 B/op       29 allocs/op
	//	BenchmarkCache/encode-16                  563797              1984 ns/op             208 B/op        1 allocs/op
	//	BenchmarkCache/decode-16                  273951              5143 ns/op            1288 B/op       31 allocs/op
}
