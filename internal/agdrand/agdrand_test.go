package agdrand_test

import (
	"math/rand/v2"
	"sync"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdrand"
	"github.com/stretchr/testify/require"
)

// routinesLimit is the number of goroutines for tests.
const routinesLimit = 512

func TestReader_race(t *testing.T) {
	t.Parallel()

	const length = 128

	reader := agdrand.NewReader(agdrand.MustNewSeed())

	wg := &sync.WaitGroup{}
	wg.Add(routinesLimit)

	startCh := make(chan struct{})
	for range routinesLimit {
		go func() {
			defer wg.Done()

			<-startCh
			for range 1_000 {
				buf := make([]byte, length)
				_, _ = reader.Read(buf)
			}
		}()
	}

	close(startCh)

	wg.Wait()
}

func TestLockedSource_race(t *testing.T) {
	t.Parallel()

	src := agdrand.NewLockedSource(rand.NewPCG(0, 0))

	wg := &sync.WaitGroup{}
	wg.Add(routinesLimit)

	startCh := make(chan struct{})
	for range routinesLimit {
		go func() {
			defer wg.Done()

			<-startCh
			for range 1_000 {
				_ = src.Uint64()
			}
		}()
	}

	close(startCh)

	wg.Wait()
}

// testSeed is a seed for tests.
var testSeed = [32]byte{}

// Sinks for benchmarks.
var (
	errSink    error
	intSink    int
	uint64Sink uint64
)

func BenchmarkReader_Read(b *testing.B) {
	const length = 16

	reader := agdrand.NewReader(testSeed)

	b.ReportAllocs()
	b.ResetTimer()

	buf := make([]byte, length)
	for range b.N {
		intSink, errSink = reader.Read(buf)
	}

	require.Equal(b, length, intSink)
	require.NoError(b, errSink)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdrand
	//	cpu: Apple M1 Pro
	//	BenchmarkReader_Read-8   	57008931	        20.60 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkLockedSource_Uint64(b *testing.B) {
	src := agdrand.NewLockedSource(rand.NewChaCha8(testSeed))

	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		uint64Sink = src.Uint64()
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdrand
	//	cpu: Apple M1 Pro
	//	BenchmarkLockedSource_Uint64-8   	77621248	        15.35 ns/op	       0 B/op	       0 allocs/op
}
