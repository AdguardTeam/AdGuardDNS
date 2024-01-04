package forward

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/pool"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// Network is a enumeration of networks UpstreamPlain supports.
type Network string

const (
	// NetworkAny means that UpstreamPlain will use the regular way of sending
	// a DNS query. First, it will send it over UDP. If for the response will
	// be truncated, it will automatically switch to using TCP.
	NetworkAny Network = ""
	// NetworkUDP means that UpstreamPlain will only use UDP.
	NetworkUDP Network = "udp"
	// NetworkTCP means that UpstreamPlain will only use TCP.
	NetworkTCP Network = "tcp"
)

const (
	// ErrQuestion is returned if the response from the upstream is invalid,
	// i.e. this is a response to a different query.
	ErrQuestion errors.Error = "response has invalid question section"
)

const (
	// poolMaxCapacity is the default pool.Pool capacity we use in
	// UpstreamPlain.
	poolMaxCapacity = 1024
	// poolIdleTimeout is the default value pool.Pool.IdleTimeout. We're not
	// making it configurable just yet, 30 seconds looks like a reasonable
	// value for DNS.
	poolIdleTimeout = time.Second * 30
	// minDNSMessageSize is a minimum theoretical size of a DNS message.
	minDNSMessageSize = 12 + 5
	// udpBufSize is the size of buffers we use for UDP messages. We use
	// 4096 since it's highly unlikely that a UDP message can be larger.
	//
	// TODO(ameshkov): consider making it configurable in the future.
	udpBufSize = 4096
	// tcpBufSize is the size of buffers we use for TCP messages.
	tcpBufSize = dns.MaxMsgSize
)

// UpstreamPlain is a simple plain DNS client.
type UpstreamPlain struct {
	// connection pools for TCP and TCP
	connsPoolUDP *pool.Pool
	connsPoolTCP *pool.Pool

	// Pools used for TCP and UDP messages buffers in order to avoid extra
	// allocations.
	udpBufs *syncutil.Pool[[]byte]
	tcpBufs *syncutil.Pool[[]byte]

	addr    netip.AddrPort
	network Network

	// timeout is the query timeout for this upstream.
	timeout time.Duration
}

// type check
var _ Upstream = (*UpstreamPlain)(nil)

// UpstreamPlainConfig is the configuration structure for a plain-DNS upstream.
type UpstreamPlainConfig struct {
	// Network is the network to use for this upstream.
	Network Network

	// Address is the address of the upstream DNS server.
	Address netip.AddrPort

	// Timeout is the optional query timeout for upstreams.  If not set, the
	// context timeout or [defaultUDPTimeout] is used in case of UDP network.
	Timeout time.Duration
}

// NewUpstreamPlain returns a new properly initialized *UpstreamPlain.  c must
// not be nil.
func NewUpstreamPlain(c *UpstreamPlainConfig) (ups *UpstreamPlain) {
	ups = &UpstreamPlain{
		udpBufs: syncutil.NewSlicePool[byte](udpBufSize),
		tcpBufs: syncutil.NewSlicePool[byte](tcpBufSize),

		addr:    c.Address,
		network: c.Network,

		timeout: c.Timeout,
	}

	ups.connsPoolUDP = pool.NewPool(poolMaxCapacity, makeConnsPoolFactory(ups, NetworkUDP))
	ups.connsPoolUDP.IdleTimeout = poolIdleTimeout
	ups.connsPoolTCP = pool.NewPool(poolMaxCapacity, makeConnsPoolFactory(ups, NetworkTCP))
	ups.connsPoolTCP.IdleTimeout = poolIdleTimeout

	return ups
}

// Exchange implements the [Upstream] interface for [*UpstreamPlain].  It
// handles gracefully the situation with truncated responses and fallbacks to
// TCP when needed.  Uses the first of context's deadline and the configured
// timeout specify exchange deadline.  Ignores [net.Error] and [io.EOF] errors
// that occur when writing response.  Returns response, network type over which
// the request has been processed and error if happened.
func (u *UpstreamPlain) Exchange(
	ctx context.Context,
	req *dns.Msg,
) (resp *dns.Msg, nw Network, err error) {
	defer func() { err = errors.Annotate(err, "upstreamplain: %w") }()

	if u.timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, u.timeout)
		defer cancel()
	}

	// First, we should try sending a DNS query over UDP.
	var fallbackToTCP bool
	fallbackToTCP, resp, err = u.exchangeUDP(ctx, req)
	if !fallbackToTCP {
		return resp, NetworkUDP, err
	}

	resp, err = u.exchangeNet(ctx, req, NetworkTCP)

	return resp, NetworkTCP, err
}

// Close implements the io.Closer interface for *UpstreamPlain.
func (u *UpstreamPlain) Close() (err error) {
	udpErr := u.connsPoolUDP.Close()
	tcpErr := u.connsPoolTCP.Close()

	return errors.Annotate(errors.Join(udpErr, tcpErr), "closing upstream: %w")
}

// String implements the fmt.Stringer interface for *UpstreamPlain.
// If upstream's network is NetworkAny, it will simply return the IP:port.
// If the network is specified, it will return address in the
// "network://IP:port" format.
func (u *UpstreamPlain) String() (str string) {
	if u.network == NetworkAny {
		return u.addr.String()
	}

	return fmt.Sprintf("%s://%s", u.network, u.addr)
}

// exchangeUDP attempts to send the DNS request over UDP.  It returns a
// fallbackToTCP flag to signal if the caller should fallback to using TCP
// instead.  This may happen if the response received over UDP was truncated and
// TCP is enabled for this upstream or if UDP is disabled.
func (u *UpstreamPlain) exchangeUDP(
	ctx context.Context,
	req *dns.Msg,
) (fallbackToTCP bool, resp *dns.Msg, err error) {
	if u.network == NetworkTCP {
		// Fallback to TCP immediately.
		return true, nil, nil
	}

	resp, err = u.exchangeNet(ctx, req, NetworkUDP)
	if err != nil {
		// The network error always causes the subsequent query attempt using
		// fresh UDP connection, so if it happened again, the upstream is likely
		// dead and using TCP appears meaningless.  See [exchangeNet].
		//
		// Thus, non-network errors are considered being related to the
		// response.  It may also happen the received response is intended for
		// another timed out request sent from the same source port, but falling
		// back to TCP in this case shouldn't hurt.
		fallbackToTCP = !isExpectedConnErr(err)

		return fallbackToTCP, resp, err
	}

	// Also, fallback to TCP if the received response is truncated and the
	// upstream isn't UDP-only.
	fallbackToTCP = u.network != NetworkUDP && resp != nil && resp.Truncated

	return fallbackToTCP, resp, nil
}

// exchangeNet sends a DNS query using the specified network (either TCP or UDP).
func (u *UpstreamPlain) exchangeNet(
	ctx context.Context,
	req *dns.Msg,
	network Network,
) (resp *dns.Msg, err error) {
	var connsPool *pool.Pool
	if network == NetworkTCP {
		connsPool = u.connsPoolTCP
	} else {
		connsPool = u.connsPoolUDP
	}

	// Get the buffer to use for packing the request and reading the response.
	// This buffer needs to be returned back to the pool once we're done.
	bufPtr := u.getBuffer(network)
	defer u.putBuffer(network, bufPtr)

	buf := (*bufPtr)

	// Pack the query into the specified buffer.
	bufReqLen, err := u.packReq(network, buf, req)
	if err != nil {
		return nil, fmt.Errorf("packing request: %w", err)
	}

	// Try connecting to the upstream.
	var conn *pool.Conn
	conn, err = connsPool.Get(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting connection: %w", err)
	}

	// err is already wrapped inside processConn.
	resp, err = u.processConn(ctx, conn, connsPool, network, req, buf, bufReqLen)
	if isExpectedConnErr(err) {
		conn, err = connsPool.Create(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating connection: %w", err)
		}

		// err is already wrapped inside processConn.
		resp, err = u.processConn(ctx, conn, connsPool, network, req, buf, bufReqLen)
	}

	return resp, err
}

// validatePlainResponse returns an error if the response is not valid for the
// original request.  This is required because we might receive a response to a
// different query, e.g. when the server is under heavy load.
func validatePlainResponse(req, resp *dns.Msg) (err error) {
	if req.Id != resp.Id {
		return dns.ErrId
	}

	if qlen := len(resp.Question); qlen != 1 {
		return fmt.Errorf("%w: only 1 question allowed; got %d", ErrQuestion, qlen)
	}

	reqQ, respQ := req.Question[0], resp.Question[0]

	if reqQ.Qtype != respQ.Qtype {
		return fmt.Errorf("%w: mismatched type %s", ErrQuestion, dns.Type(respQ.Qtype))
	}

	// Compare the names case-insensitively, just like CoreDNS does.
	if !strings.EqualFold(reqQ.Name, respQ.Name) {
		return fmt.Errorf("%w: mismatched name %q", ErrQuestion, respQ.Name)
	}

	return nil
}

// defaultUDPTimeout is the default timeout for waiting a valid DNS message or
// network error over UDP protocol.
const defaultUDPTimeout = 1 * time.Minute

// processConn writes the query to the connection and then reads the response
// from it.  We might be dealing with an idle dead connection so if we get
// a network error here, we'll attempt to open a new connection and call this
// function again.
//
// TODO(ameshkov): 7 parameters in a method is not okay, rework this.
func (u *UpstreamPlain) processConn(
	ctx context.Context,
	conn *pool.Conn,
	connsPool *pool.Pool,
	network Network,
	req *dns.Msg,
	buf []byte,
	bufReqLen int,
) (resp *dns.Msg, err error) {
	// Make sure that we return the connection to the pool in the end or close
	// if there was any error.
	defer func() {
		if err != nil {
			err = errors.WithDeferred(err, conn.Close())
		} else {
			err = connsPool.Put(conn)
		}
	}()

	// Prepare a context with a deadline if needed.
	deadline, ok := ctx.Deadline()
	if !ok && network == NetworkUDP {
		deadline, ok = time.Now().Add(defaultUDPTimeout), true
	}

	if ok {
		err = conn.SetDeadline(deadline)
		if err != nil {
			return nil, fmt.Errorf("setting deadline: %w", err)
		}
	}

	// Write the request to the connection.
	_, err = conn.Write(buf[:bufReqLen])
	if err != nil {
		return nil, fmt.Errorf("writing request: %w", err)
	}

	return u.readValidMsg(req, network, conn, buf)
}

// readValidMsg reads the response from conn to buf, parses and validates it.
func (u *UpstreamPlain) readValidMsg(
	req *dns.Msg,
	network Network,
	conn net.Conn,
	buf []byte,
) (resp *dns.Msg, err error) {
	resp, err = u.readMsg(network, conn, buf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	err = validatePlainResponse(req, resp)
	if err != nil {
		return resp, fmt.Errorf("validating %s response: %w", network, err)
	}

	return resp, nil
}

// readMsg reads the response from the specified connection and parses it.
func (u *UpstreamPlain) readMsg(network Network, conn net.Conn, buf []byte) (*dns.Msg, error) {
	var err error
	var n int

	if network == NetworkTCP {
		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			return nil, fmt.Errorf("reading binary data: %w", err)
		}

		n, err = io.ReadFull(conn, buf[:length])
		if err != nil {
			return nil, fmt.Errorf("reading full: %w", err)
		}
	} else {
		n, err = conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("udp network reading: %w", err)
		}
	}

	if n < minDNSMessageSize {
		return nil, fmt.Errorf("invalid msg: %w", dns.ErrShortRead)
	}

	ret := &dns.Msg{}
	err = ret.Unpack(buf)
	if err != nil {
		return nil, fmt.Errorf("unpacking msg: %w", err)
	}

	return ret, nil
}

// packReq packs the DNS query to the specified buffer.
func (u *UpstreamPlain) packReq(network Network, buf []byte, req *dns.Msg) (n int, err error) {
	reqLen := req.Len()
	if reqLen > dns.MaxMsgSize {
		return 0, dns.ErrBuf
	}

	if network == NetworkTCP {
		if reqLen > len(buf)-2 {
			return 0, dns.ErrBuf
		}

		binary.BigEndian.PutUint16(buf, uint16(reqLen))
		_, err = req.PackBuffer(buf[2:])

		return reqLen + 2, err
	}

	if reqLen > len(buf) {
		return 0, dns.ErrBuf
	}

	_, err = req.PackBuffer(buf)

	return reqLen, err
}

// getBuffer gets a bytes buffer that used for packing the request and then for
// reading the response.
func (u *UpstreamPlain) getBuffer(network Network) (bufPtr *[]byte) {
	switch network {
	case NetworkTCP:
		return u.tcpBufs.Get()
	case NetworkUDP:
		return u.udpBufs.Get()
	default:
		panic(fmt.Errorf("no bufs for network %q in get", network))
	}
}

// putBuffer puts the buffer back to the corresponding pool.
func (u *UpstreamPlain) putBuffer(network Network, bufPtr *[]byte) {
	switch network {
	case NetworkTCP:
		u.tcpBufs.Put(bufPtr)
	case NetworkUDP:
		u.udpBufs.Put(bufPtr)
	default:
		panic(fmt.Errorf("no bufs for network %q in put", network))
	}
}

// makeConnsPoolFactory makes a pool.Factory method for the specified address and
// network.
func makeConnsPoolFactory(u *UpstreamPlain, network Network) (f pool.Factory) {
	var dialNetwork string
	switch network {
	case NetworkTCP:
		dialNetwork = "tcp"
	case NetworkUDP:
		dialNetwork = "udp"
	default:
		panic("invalid network passed to makeConnsPoolFactory")
	}

	return func(ctx context.Context) (conn net.Conn, err error) {
		deadline, ok := ctx.Deadline()
		var timeout time.Duration
		if ok {
			timeout = time.Until(deadline)
		}

		return net.DialTimeout(dialNetwork, u.addr.String(), timeout)
	}
}

// isExpectedConnErr returns true if the error is expected.  In this case,
// we will make a second attempt to process the request.
func isExpectedConnErr(err error) (is bool) {
	var netErr net.Error

	return err != nil && (errors.As(err, &netErr) || errors.Is(err, io.EOF))
}
