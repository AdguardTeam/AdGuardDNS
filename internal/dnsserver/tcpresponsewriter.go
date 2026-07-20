package dnsserver

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/messagetap"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// tcpResponseWriter implements ResponseWriter interface for a DNS-over-TCP or
// a DNS-over-TLS server.
type tcpResponseWriter struct {
	messageTap messagetap.Interface
	respPool   *syncutil.Pool[[]byte]
	// writeMu is used to serialize the sequence of setting the write deadline,
	// writing to a connection, and resetting the write deadline, across
	// multiple goroutines in the pipeline.
	writeMu      *sync.Mutex
	conn         net.Conn
	writeTimeout time.Duration
	idleTimeout  time.Duration
}

// type check
var _ ResponseWriter = (*tcpResponseWriter)(nil)

// LocalAddr implements the [ResponseWriter] interface for *tcpResponseWriter.
func (r *tcpResponseWriter) LocalAddr() (addr net.Addr) {
	return r.conn.LocalAddr()
}

// RemoteAddr implements the [ResponseWriter] interface for *tcpResponseWriter.
func (r *tcpResponseWriter) RemoteAddr() (addr net.Addr) {
	return r.conn.RemoteAddr()
}

// WriteMsg implements the [ResponseWriter] interface for *tcpResponseWriter.
func (r *tcpResponseWriter) WriteMsg(ctx context.Context, req, resp *dns.Msg) (err error) {
	ctx = context.WithoutCancel(ctx)

	si := MustServerInfoFromContext(ctx)
	normalizeTCP(si.Proto, req, resp)
	r.addTCPKeepAlive(req, resp)

	bufPtr := r.respPool.Get()
	defer r.respPool.Put(bufPtr)

	b, err := packWithPrefix(resp, *bufPtr)
	if err != nil {
		return fmt.Errorf("tcp: packing response: %w", err)
	}

	*bufPtr = b

	tapResponse(ctx, r.messageTap, r.LocalAddr(), r.RemoteAddr(), b[2:])

	// Serialize the write deadline setting on the shared connection, since
	// messages accepted over TCP are processed out of order.
	r.writeMu.Lock()
	defer r.writeMu.Unlock()

	// Use SetWriteDeadline as opposed to SetDeadline, since the TLS handshake
	// has already been performed, so conn.Write shouldn't perform reads.
	withWriteDeadline(ctx, r.writeTimeout, r.conn, func() {
		_, err = r.conn.Write(b)
	})

	if err != nil {
		return &WriteError{
			Err:      err,
			Protocol: "tcp",
		}
	}

	return nil
}

// addTCPKeepAlive adds a ENDS0 TCP keep-alive option to the DNS response as per
// RFC 7828.  This option specifies the desired idle connection timeout.  req
// and resp must not be nil.
func (r *tcpResponseWriter) addTCPKeepAlive(req, resp *dns.Msg) {
	reqOpt := req.IsEdns0()
	respOpt := resp.IsEdns0()

	if reqOpt == nil ||
		respOpt == nil ||
		findOption[*dns.EDNS0_TCP_KEEPALIVE](reqOpt) == nil {
		// edns-tcp-keepalive can only be added if it's explicitly indicated in
		// the DNS request that it's supported.
		return
	}

	keepAliveOpt := findOption[*dns.EDNS0_TCP_KEEPALIVE](respOpt)
	if keepAliveOpt == nil {
		keepAliveOpt = &dns.EDNS0_TCP_KEEPALIVE{
			Code: dns.EDNS0TCPKEEPALIVE,
		}
		respOpt.Option = append(respOpt.Option, keepAliveOpt)
	}

	// Should be specified in units of 100 milliseconds encoded in network byte
	// order.
	// #nosec G115 -- r.idleTimeout comes from [ConfigDNS.TCPIdleTimeout], which
	// is validated in [newServerDNS].
	keepAliveOpt.Timeout = uint16(r.idleTimeout.Milliseconds() / 100)
}
