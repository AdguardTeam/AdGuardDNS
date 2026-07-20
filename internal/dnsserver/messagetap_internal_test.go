package dnsserver

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

// testLogger is the common logger for tests.
var testLogger = slogutil.NewDiscardLogger()

func Benchmark_DNSTap_noListener(b *testing.B) {
	socketPath := filepath.Join(b.TempDir(), "dt.sock")
	tapper, err := messagetap.NewDefaultTapper(testLogger, socketPath)
	require.NoError(b, err)

	tap := messagetap.NewDNSTap(&messagetap.DNSTapConfig{
		Logger:              testLogger,
		SocketPath:          socketPath,
		Tapper:              tapper,
		CheckInterval:       testTimeout,
		CheckConnectTimeout: testTimeout,
	})

	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12345"))
	payload := newTestPayload(b)

	ctx := context.Background()

	b.ReportAllocs()
	for b.Loop() {
		tapRequest(ctx, tap, addr, addr, payload)
		tapResponse(ctx, tap, addr, addr, payload)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	//	cpu: Apple M1 Pro
	//	Benchmark_Tap_noListener-8   	49396275	        24.07 ns/op	       0 B/op	       0 allocs/op
}

func Benchmark_TapRequest(b *testing.B) {
	tap := newTestDNSTap(b)

	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12345"))
	payload := newTestPayload(b)

	ctx := context.Background()

	// Warmup to fill the pools and the slices.
	tapRequest(ctx, tap, addr, addr, payload)

	b.ReportAllocs()
	for b.Loop() {
		tapRequest(ctx, tap, addr, addr, payload)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	//	cpu: Apple M1 Pro
	//	Benchmark_TapRequest-8   	 3146770	       319.8 ns/op	      27 B/op	       3 allocs/op
}

func Benchmark_TapResponse(b *testing.B) {
	tap := newTestDNSTap(b)

	addr := net.TCPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:12345"))
	payload := newTestPayload(b)

	ctx := context.Background()

	// Warmup to fill the pools and the slices.
	tapResponse(ctx, tap, addr, addr, payload)

	b.ReportAllocs()
	for b.Loop() {
		tapResponse(ctx, tap, addr, addr, payload)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	//	cpu: Apple M1 Pro
	//	Benchmark_TapResponse-8   	 2929508	       343.4 ns/op	      27 B/op	       3 allocs/op
}

// newTestPayload returns a new payload bytes for tests.
func newTestPayload(tb testing.TB) (payload []byte) {
	tb.Helper()

	const testDomainName = "test.example"

	req := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id: dns.Id(),
		},
		Question: []dns.Question{{
			Name:   dns.Fqdn(testDomainName),
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}
	payload, err := req.Pack()
	require.NoError(tb, err)

	return payload
}

// newTestDNSTap returns a new [*messagetap.DNSTap] ready for tests.
func newTestDNSTap(tb testing.TB) (tap *messagetap.DNSTap) {
	tb.Helper()

	socketPath := filepath.Join(tb.TempDir(), "dt.sock")
	startReadSocket(tb, socketPath)

	tapper, err := messagetap.NewDefaultTapper(testLogger, socketPath)
	require.NoError(tb, err)

	tap = messagetap.NewDNSTap(&messagetap.DNSTapConfig{
		Logger:              testLogger,
		SocketPath:          socketPath,
		Tapper:              tapper,
		CheckInterval:       testTimeout,
		CheckConnectTimeout: testTimeout,
	})

	servicetest.RequireRun(tb, tap, testTimeout)

	return tap
}

// startReadSocket creates a unix socket listener for the specified socket path
// and drains messages from it.
func startReadSocket(tb testing.TB, socketPath string) {
	tb.Helper()

	const outputChannelSize = 32

	msgCh := make(chan []byte, outputChannelSize)
	tb.Cleanup(func() {
		close(msgCh)
	})

	go func() {
		for range msgCh {
			// Drain out the channel to prevent blocking when the channel is
			// full.
		}
	}()

	in, err := dnstap.NewFrameStreamSockInputFromPath(socketPath)
	require.NoError(tb, err)

	go in.ReadInto(msgCh)
}
