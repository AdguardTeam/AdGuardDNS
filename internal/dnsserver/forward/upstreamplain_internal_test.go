package forward

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/fakenet"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func BenchmarkUpstreamPlain_ReadMsg(b *testing.B) {
	req := dnsservertest.NewReq(dnsservertest.FQDN, dns.TypeA, dns.ClassINET)
	resp := dnsservertest.NewResp(dns.RcodeSuccess, req, dnsservertest.SectionAnswer{
		dnsservertest.NewA(dnsservertest.FQDN, 10, netip.MustParseAddr("192.0.2.0")),
	})

	data, err := resp.Pack()
	require.NoError(b, err)

	tcpLen := binary.BigEndian.AppendUint16(nil, uint16(len(data)))
	tcpData := append(tcpLen, data...)

	ups := NewUpstreamPlain(&UpstreamPlainConfig{})
	testutil.CleanupAndRequireSuccess(b, ups.Close)

	b.Run("udp", func(b *testing.B) {
		reader := bytes.NewReader(data)
		conn := &fakenet.Conn{
			OnRead: reader.Read,
		}

		bufPtr := ups.getBuffer(NetworkUDP)
		defer ups.putBuffer(NetworkUDP, bufPtr)

		// Warmup to fill the slices.
		buf := *bufPtr
		_, err = ups.readMsg(NetworkUDP, conn, buf)
		require.NoError(b, err)

		b.ReportAllocs()
		for b.Loop() {
			reader.Reset(data)
			_, err = ups.readMsg(NetworkUDP, conn, buf)
		}

		require.NoError(b, err)
	})

	b.Run("tcp", func(b *testing.B) {
		reader := bytes.NewReader(tcpData)
		conn := &fakenet.Conn{
			OnRead: reader.Read,
		}

		bufPtr := ups.getBuffer(NetworkTCP)
		defer ups.putBuffer(NetworkTCP, bufPtr)

		// Warmup to fill the slices.
		buf := *bufPtr
		_, err = ups.readMsg(NetworkTCP, conn, buf)
		require.NoError(b, err)

		b.ReportAllocs()
		for b.Loop() {
			reader.Reset(tcpData)
			_, err = ups.readMsg(NetworkTCP, conn, buf)
		}

		require.NoError(b, err)
	})

	// Most recent results:
	//	goos: darwin
	//	goarch: arm64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/forward
	//	cpu: Apple M4 Pro
	//	BenchmarkUpstreamPlain_ReadMsg/udp-14         	 5739868	       191.6 ns/op	     320 B/op	       8 allocs/op
	//	BenchmarkUpstreamPlain_ReadMsg/tcp-14         	 6143383	       195.8 ns/op	     320 B/op	       8 allocs/op
}
