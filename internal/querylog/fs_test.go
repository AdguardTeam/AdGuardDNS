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
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileSystem_Write(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), t.Name())
	require.NoError(t, err)

	l := querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger:   slogutil.NewDiscardLogger(),
		Path:     f.Name(),
		RandSeed: 0,
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
  "rn":35121,
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
  "rn":47387,
  "f":1,
  "s":1,
  "p":8
}`) + "\n"

		assert.Equal(t, want, string(b))
	})
}

var errSink error

func BenchmarkFileSystem_Write_file(b *testing.B) {
	f, err := os.CreateTemp(b.TempDir(), b.Name())
	require.NoError(b, err)

	l := querylog.NewFileSystem(&querylog.FileSystemConfig{
		Logger:   slogutil.NewDiscardLogger(),
		Path:     f.Name(),
		RandSeed: 0,
	})

	e := testEntry()
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		errSink = l.Write(ctx, e)
	}

	require.NoError(b, errSink)

	// Most recent result, on a ThinkPad X13:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/querylog
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkFileSystem_Write_file-16    	  122740	     12386 ns/op	     248 B/op	       5 allocs/op
}
