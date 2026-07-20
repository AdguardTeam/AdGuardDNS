package messagetap_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// outputChannelSize is the number of frames that can be buffered in the output
// channel.
const outputChannelSize = 32

func TestDefaultTapper(t *testing.T) {
	t.Parallel()

	socketPath := filepath.Join(t.TempDir(), "dt.sock")
	msgCh := make(chan []byte, outputChannelSize)
	startReadSocket(t, socketPath, msgCh)

	tapper, err := messagetap.NewDefaultTapper(testLogger, socketPath)
	require.NoError(t, err)

	servicetest.RequireRun(t, tapper, testTimeout)

	req := dnsservertest.NewReq(dnsservertest.FQDN, dns.TypeA, dns.ClassINET)
	payload, err := req.Pack()
	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, testTimeout)
	tapper.Tap(ctx, payload)

	got, ok := testutil.RequireReceive(t, msgCh, testTimeout)
	require.True(t, ok)

	msg := &dns.Msg{}
	err = msg.Unpack(got)
	require.NoError(t, err)

	assert.Len(t, msg.Question, 1)
	assert.Equal(t, req.Question[0], msg.Question[0])
}

func BenchmarkDefaultTapper(b *testing.B) {
	socketPath := filepath.Join(b.TempDir(), "dt.sock")
	msgCh := make(chan []byte, outputChannelSize)
	b.Cleanup(func() {
		close(msgCh)
	})

	startReadSocket(b, socketPath, msgCh)

	go func() {
		for range msgCh {
			// Drain out the channel to prevent blocking when the channel is
			// full.
		}
	}()

	tapper, err := messagetap.NewDefaultTapper(slogutil.New(&slogutil.Config{Level: slogutil.LevelInfo}), socketPath)
	require.NoError(b, err)

	servicetest.RequireRun(b, tapper, testTimeout)

	req := dnsservertest.NewReq(dnsservertest.FQDN, dns.TypeA, dns.ClassINET)
	payload, err := req.Pack()
	require.NoError(b, err)

	ctx := context.Background()

	// Warmup to fill the pools and the slices.
	tapper.Tap(ctx, payload)

	b.ReportAllocs()
	for b.Loop() {
		tapper.Tap(ctx, payload)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap
	//	cpu: Apple M1 Pro
	//	BenchmarkDefaultTapper-8   	21140251	        50.49 ns/op	       1 B/op	       0 allocs/op
}

// startReadSocket creates a unix socket listener for the specified socket path
// and starts reading messages from it into msgCh.
func startReadSocket(tb testing.TB, socketPath string, msgCh chan []byte) {
	tb.Helper()

	in, err := dnstap.NewFrameStreamSockInputFromPath(socketPath)
	require.NoError(tb, err)

	go in.ReadInto(msgCh)
}
