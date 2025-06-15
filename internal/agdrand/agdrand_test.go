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

func BenchmarkReader_Read(b *testing.B) {
	const length = 16

	reader := agdrand.NewReader(testSeed)

	var n int
	var err error

	b.ReportAllocs()
	buf := make([]byte, length)
	for b.Loop() {
		n, err = reader.Read(buf)
	}

	require.Equal(b, length, n)
	require.NoError(b, err)

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdrand
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkReader_Read-12    	38364720	        28.48 ns/op	       0 B/op	       0 allocs/op
}

func BenchmarkLockedSource_Uint64(b *testing.B) {
	src := agdrand.NewLockedSource(rand.NewChaCha8(testSeed))

	b.ReportAllocs()
	for range b.N {
		_ = src.Uint64()
	}

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/agdrand
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkLockedSource_Uint64-12    	59585797	        18.13 ns/op	       0 B/op	       0 allocs/op
}
