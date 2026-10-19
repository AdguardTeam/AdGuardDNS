package dnsserver

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

// quicResponseWriter is an implementation of the [ResponseWriter] interface for
// the DNS-over-QUIC server.
type quicResponseWriter struct {
	clock        timeutil.Clock
	messageTap   messagetap.Interface
	laddr        net.Addr
	raddr        net.Addr
	respPool     *syncutil.Pool[[]byte]
	conn         *quic.Conn
	stream       *quic.Stream
	writeTimeout time.Duration
}

// type check
var _ ResponseWriter = (*quicResponseWriter)(nil)

// LocalAddr implements the [ResponseWriter] interface for *quicResponseWriter.
func (r *quicResponseWriter) LocalAddr() (addr net.Addr) {
	return r.laddr
}

// RemoteAddr implements the [ResponseWriter] interface for *quicResponseWriter.
func (r *quicResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.raddr
}

// WriteMsg implements the [ResponseWriter] interface for *quicResponseWriter.
func (r *quicResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	ctx = context.WithoutCancel(ctx)

	normalizeTCP(ProtoDoQ, req, resp)

	bufPtr := r.respPool.Get()
	defer r.respPool.Put(bufPtr)

	b, err := packWithPrefix(resp, *bufPtr)
	if err != nil {
		closeErr := r.conn.CloseWithError(DOQCodeProtocolError, "")

		return fmt.Errorf("packing quic response: %w", errors.WithDeferred(err, closeErr))
	}

	*bufPtr = b

	tapResponse(ctx, r.clock.Now(), r.messageTap, r.laddr, r.raddr, b[2:])

	withWriteDeadline(ctx, r.writeTimeout, r.stream, func() {
		_, err = r.stream.Write(b)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "quic",
		}
	}

	return nil
}
