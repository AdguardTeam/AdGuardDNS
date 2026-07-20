package dnsserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

const (
	// testTimeout is a common timeout for tests.
	testTimeout = 1 * time.Second

	// testDomain is a common FQDN value for tests.
	testFQDN = "example.org."

	// testTCPRequestBufferInitialLength is a common length for a
	// [ServerDNS.tcpPool] initialization in tests.
	testTCPRequestBufferInitialLength = 2
)

var (
	// testIPv4 is a common IPv4 value for tests.
	testIPv4 = netip.MustParseAddr("192.0.2.0")

	// localhostNetIPv4 is the [net.IP] IPv4 localhost address "127.0.0.1".
	localhostNetIPv4 net.IP = netutil.IPv4Localhost().AsSlice()

	// testLocalAddr is a common local address for tests.
	testLocalAddr = &net.TCPAddr{
		IP:   localhostNetIPv4,
		Port: 5757,
	}

	// testRemoteAddr is a common remote address for tests.
	testRemoteAddr = &net.TCPAddr{
		IP:   localhostNetIPv4,
		Port: 5858,
	}
)

func BenchmarkServerDNS_ReadTCPMsg(b *testing.B) {
	server := &ServerDNS{
		tcpPool: syncutil.NewSlicePool[byte](testTCPRequestBufferInitialLength),
		ServerBase: &ServerBase{
			messageTap: messagetap.Empty{},
			clock:      timeutil.SystemClock{},
			metrics:    EmptyMetricsListener{},
		},
	}

	req := &dns.Msg{}
	req.SetQuestion(testFQDN, dns.TypeA)

	resp := &dns.Msg{}
	resp.SetReply(req)
	resp.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   testFQDN,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
			},
			A: testIPv4.AsSlice(),
		},
	}

	data, err := resp.Pack()
	require.NoError(b, err)

	dataLen := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	data = append(dataLen, data...)

	reader := bytes.NewReader(data)
	conn := &fakenet.Conn{
		OnRead:            reader.Read,
		OnSetReadDeadline: func(_ time.Time) (err error) { return nil },
		OnRemoteAddr: func() (raddr net.Addr) {
			return testRemoteAddr
		},
		OnLocalAddr: func() (laddr net.Addr) {
			return testLocalAddr
		},
	}

	ctx := testutil.ContextWithTimeout(b, testTimeout)

	// Warmup to fill the pools.
	_, err = server.readTCPMsg(ctx, conn, testTimeout)
	require.NoError(b, err)

	b.ReportAllocs()
	for b.Loop() {
		reader.Reset(data)
		_, err = server.readTCPMsg(ctx, conn, testTimeout)
	}

	require.NoError(b, err)

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver
	//	cpu: Apple M1 Pro
	//	BenchmarkServerDNS_ReadTCPMsg-8   	 3209209	       376.1 ns/op	     320 B/op	       8 allocs/op
}
