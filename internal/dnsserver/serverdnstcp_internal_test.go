package dnsserver

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
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

// testIPv4 is a common IPv4 value for tests.
var testIPv4 = netip.MustParseAddr("192.0.2.0")

func BenchmarkServerDNS_ReadTCPMsg(b *testing.B) {
	server := &ServerDNS{
		tcpPool: syncutil.NewSlicePool[byte](testTCPRequestBufferInitialLength),
		ServerBase: &ServerBase{
			metrics: EmptyMetricsListener{},
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
	//	cpu: Apple M4 Pro
	//	BenchmarkServerDNS_ReadTCPMsg-14    	 4720626	       239.9 ns/op	     320 B/op	       8 allocs/op
}
