package querylog_test

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSystem_Write(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), t.Name())
	require.NoError(t, err)

	l := querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger:    slogutil.NewDiscardLogger(),
		Metrics:   querylog.EmptyMetrics{},
		Semaphore: syncutil.EmptySemaphore{},
		Path:      f.Name(),
		RandSeed:  [32]byte{},
	})

	ctx := context.Background()
	e := testEntry()

	err = l.Write(ctx, e)
	require.NoError(t, err)

	_, err = f.Seek(0, io.SeekStart)
	require.NoError(t, err)

	b, err := io.ReadAll(f)
	require.NoError(t, err)

	rep := strings.NewReplacer(
		" ", "",
		"\n", "",
		"REQID", testRequestID.String(),
	)
	want := rep.Replace(`
{
  "u":"REQID",
  "b":"prof1234",
  "i":"dev1234",
  "c":"RU",
  "d":"US",
  "n":"example.com.",
  "l":"adguard_dns_filter",
  "m":"||example.com^",
  "t":123000,
  "a":1234,
  "e":5,
  "q":1,
  "r":0,
  "rn":13933,
  "f":2,
  "s":1,
  "p":8
}`) + "\n"

	assert.Equal(t, want, string(b))

	t.Run("nxdomain", func(t *testing.T) {
		e = testEntry()
		e.RequestResult, e.ResponseResult = nil, nil
		e.ResponseCountry = geoip.CountryNone
		e.ResponseCode = dns.RcodeNameError

		err = l.Write(ctx, e)
		require.NoError(t, err)

		b, err = io.ReadAll(f)
		require.NoError(t, err)

		rep = strings.NewReplacer(
			" ", "",
			"\n", "",
			"REQID", testRequestID.String(),
		)
		want = rep.Replace(`
{
  "u":"REQID",
  "b":"prof1234",
  "i":"dev1234",
  "c":"RU",
  "n":"example.com.",
  "t":123000,
  "a":1234,
  "e":5,
  "q":1,
  "r":3,
  "rn":10182,
  "f":1,
  "s":1,
  "p":8
}`) + "\n"

		assert.Equal(t, want, string(b))
	})
}

func BenchmarkFileSystem_Write_file(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), b.Name())
	require.NoError(b, err)

	l := querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger:    slogutil.NewDiscardLogger(),
		Metrics:   querylog.EmptyMetrics{},
		Semaphore: syncutil.EmptySemaphore{},
		Path:      f.Name(),
		RandSeed:  [32]byte{},
	})

	e := testEntry()
	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		err = l.Write(ctx, e)
	}

	require.NoError(b, err)

	// Most recent results:
	//
	// goos: darwin
	// goarch: amd64
	// pkg: github.com/AdguardTeam/AdGuardDNS/internal/querylog
	// cpu: Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz
	// BenchmarkFileSystem_Write_file-12    	   41662	     55338 ns/op	     297 B/op	       5 allocs/op
}
