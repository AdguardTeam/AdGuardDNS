package messagetap_test

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

// newSocketPath starts a Unix domain socket listener and returns the path to
// the socket.  The socket is automatically cleaned up when the test finishes.
func newSocketPath(tb testing.TB) (p string) {
	tb.Helper()

	p = filepath.Join(tb.TempDir(), "dt.sock")
	startUnixListener(tb, p)

	return p
}

// startUnixListener starts a Unix domain socket listener.  Connections are
// accepted and immediately closed so the socket stays open.
func startUnixListener(tb testing.TB, socketPath string) {
	tb.Helper()

	l, err := net.Listen("unix", socketPath)
	require.NoError(tb, err)

	testutil.CleanupAndRequireSuccess(tb, l.Close)

	go func() {
		for {
			conn, lErr := l.Accept()
			if errors.Is(lErr, net.ErrClosed) {
				return
			}

			if lErr != nil {
				tb.Logf("listener accept error: %v", lErr)

				return
			}

			require.NoError(testutil.NewPanicT(tb), conn.Close())
		}
	}()
}

func TestDNSTap(t *testing.T) {
	t.Parallel()

	socketPath := newSocketPath(t)

	tapCh := make(chan []byte, 1)

	tapper := &testTapper{
		OnTap: func(_ context.Context, payload []byte) {
			testutil.RequireSend(testutil.NewPanicT(t), tapCh, payload, testTimeout)
		},
		OnStart:    func(_ context.Context) (err error) { return nil },
		OnShutdown: func(_ context.Context) (err error) { return nil },
	}

	d := messagetap.NewDNSTap(&messagetap.DNSTapConfig{
		Logger:        testLogger,
		Tapper:        tapper,
		SocketPath:    socketPath,
		CheckInterval: testTimeout / 2,
	})

	servicetest.RequireRun(t, d, testTimeout)

	laddr := netip.MustParseAddrPort("127.0.0.1:53")
	raddr := netip.MustParseAddrPort("192.0.2.1:12345")

	ctx := testutil.ContextWithTimeout(t, testTimeout)

	// Retry until the listener-check goroutine detects the socket and sets
	// hasListener to true, after which TapRequest will forward the message.
	require.Eventually(t, func() (ok bool) {
		d.TapRequest(ctx, laddr, raddr, []byte("hello"))
		select {
		case <-tapCh:
			return true
		default:
			return false
		}
	}, testTimeout, testTimeout/10)

	reqPayload := []byte("ping")
	respPayload := []byte("pong")

	d.TapRequest(ctx, laddr, raddr, reqPayload)
	gotReq, ok := testutil.RequireReceive(t, tapCh, testTimeout)
	require.True(t, ok)
	require.NotNil(t, gotReq)

	assertDNSTap(t, gotReq, raddr, laddr, dnstap.Message_CLIENT_QUERY, reqPayload, nil)

	d.TapResponse(ctx, laddr, raddr, respPayload)
	gotResp, ok := testutil.RequireReceive(t, tapCh, testTimeout)
	require.True(t, ok)
	require.NotNil(t, gotResp)

	assertDNSTap(t, gotResp, raddr, laddr, dnstap.Message_CLIENT_RESPONSE, nil, respPayload)
}

// assertDNSTap is a helper function that asserts that the given data is a valid
// [dnstap.Dnstap] message with the expected fields.
func assertDNSTap(
	tb testing.TB,
	data []byte,
	raddr netip.AddrPort,
	laddr netip.AddrPort,
	msgType dnstap.Message_Type,
	req []byte,
	resp []byte,
) {
	tb.Helper()

	dt := &dnstap.Dnstap{}
	err := proto.Unmarshal(data, dt)
	require.NoError(tb, err)

	require.NotNil(tb, dt)

	assert.Equal(tb, dnstap.Dnstap_MESSAGE.Enum(), dt.Type)

	require.NotNil(tb, dt.Message)

	assert.Equal(tb, msgType.Enum(), dt.Message.Type)
	assert.Equal(tb, dnstap.SocketFamily_INET.Enum(), dt.Message.SocketFamily)
	assert.Equal(tb, raddr.Addr(), netip.AddrFrom4([4]byte(dt.Message.QueryAddress)))
	assert.Equal(tb, uint32(raddr.Port()), *dt.Message.QueryPort)
	assert.Equal(tb, laddr.Addr(), netip.AddrFrom4([4]byte(dt.Message.ResponseAddress)))
	assert.Equal(tb, uint32(laddr.Port()), *dt.Message.ResponsePort)
	assert.Equal(tb, req, dt.Message.QueryMessage)
	assert.Equal(tb, resp, dt.Message.ResponseMessage)
}

func BenchmarkDNSTap(b *testing.B) {
	socketPath := newSocketPath(b)

	d := messagetap.NewDNSTap(&messagetap.DNSTapConfig{
		Logger:        testLogger,
		Tapper:        messagetap.EmptyTapper{},
		SocketPath:    socketPath,
		CheckInterval: testTimeout / 2,
	})

	servicetest.RequireRun(b, d, testTimeout)

	laddr := netip.MustParseAddrPort("127.0.0.1:53")
	raddr := netip.MustParseAddrPort("192.0.2.1:12345")
	payload := []byte("benchmark-request-payload")

	ctx := testutil.ContextWithTimeout(b, testTimeout)

	// Wait until the socket is ready.
	require.EventuallyWithT(b, func(c *assert.CollectT) {
		conn, err := net.DialTimeout("unix", socketPath, messagetap.DefaultCheckConnectTimeout)
		require.NoError(b, err)
		require.NoError(b, conn.Close())
	}, testTimeout, testTimeout/10)

	// Warmup to fill the pools and the slices.
	d.TapRequest(ctx, laddr, raddr, payload)
	d.TapResponse(ctx, laddr, raddr, payload)

	b.ReportAllocs()
	for b.Loop() {
		d.TapRequest(ctx, laddr, raddr, payload)
		d.TapResponse(ctx, laddr, raddr, payload)
	}

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap
	//	cpu: Apple M1 Pro
	//	BenchmarkDNSTap-8   	 2343468	       427.4 ns/op	      27 B/op	       6 allocs/op
}
