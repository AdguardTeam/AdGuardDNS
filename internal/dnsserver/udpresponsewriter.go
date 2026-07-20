package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/miekg/dns"
)

// udpResponseWriter is a ResponseWriter implementation for DNS-over-UDP.
type udpResponseWriter struct {
	messageTap   messagetap.Interface
	udpSession   netext.PacketSession
	conn         net.PacketConn
	writeTimeout time.Duration
	maxRespSize  uint16
}

// type check
var _ ResponseWriter = (*udpResponseWriter)(nil)

// LocalAddr implements the [ResponseWriter] interface for *udpResponseWriter.
func (r *udpResponseWriter) LocalAddr() (addr net.Addr) {
	// Don't use r.conn.LocalAddr(), since udpSession may actually contain the
	// decoded OOB data, including the real local (dst) address.
	return r.udpSession.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *udpResponseWriter.
func (r *udpResponseWriter) RemoteAddr() (addr net.Addr) {
	// Don't use r.conn.RemoteAddr(), since udpSession may actually contain the
	// decoded OOB data, including the real remote (src) address.
	return r.udpSession.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *udpResponseWriter.
func (r *udpResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	ctx = context.WithoutCancel(ctx)

	normalize(NetworkUDP, ProtoDNS, req, resp, r.maxRespSize)

	// NOTE:  Do not use pools since WriteToSession implementations can retain
	// the bytes written to them.
	//
	// TODO(a.garipov):  Think of ways to improve that.  Perhaps some form of
	// association of the pool with the packet session.
	b, err := resp.PackBuffer(make([]byte, dns.MinMsgSize))
	if err != nil {
		return fmt.Errorf("udp: packing response: %w", err)
	}

	tapResponse(ctx, r.messageTap, r.LocalAddr(), r.RemoteAddr(), b)

	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = netext.WriteToSession(r.conn, b, r.udpSession)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "udp",
		}
	}

	return nil
}
