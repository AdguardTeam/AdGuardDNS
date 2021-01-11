package upstream

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type Proxy struct {
	addr     string
	udpConns *connsPool // pool with active UDP connections
	tcpConns *connsPool // pool with active TCP connections
	udpBuffs sync.Pool  // pool with smaller byte arrays for UDP
	tcpBuffs sync.Pool  // pool with larger byte arrays for TCP
}

// NewProxy - creates a new Proxy instance for the specified IP address
func NewProxy(addr string) (*Proxy, error) {
	dnsAddr := addr

	if _, _, err := net.SplitHostPort(dnsAddr); err != nil {
		ip := net.ParseIP(addr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP addr: %s", addr)
		}

		if ip.To4() == nil {
			dnsAddr = fmt.Sprintf("[%s]:53", dnsAddr)
		} else {
			dnsAddr = fmt.Sprintf("%s:53", dnsAddr)
		}
	}

	host, port, err := net.SplitHostPort(dnsAddr)
	if err != nil || host == "" || port == "" || net.ParseIP(host) == nil {
		return nil, fmt.Errorf("invalid addr: %s", addr)
	}

	p := &Proxy{
		addr:     dnsAddr,
		udpConns: &connsPool{},
		tcpConns: &connsPool{},
		udpBuffs: sync.Pool{
			New: func() interface{} {
				var b = make([]byte, 4*1024)
				return &b
			},
		},
		tcpBuffs: sync.Pool{
			New: func() interface{} {
				var b = make([]byte, dns.MaxMsgSize)
				return &b
			},
		},
	}

	return p, nil
}

// Sends a DNS query to the proxy and returns the response
func (p *Proxy) Exchange(m *dns.Msg) (*dns.Msg, error) {
	start := time.Now()
	var ret *dns.Msg
	var cached bool
	var err error
	proto := "udp"

	deadline := time.Now().Add(readTimeout)

	for time.Now().Before(deadline) {
		ret, cached, err = p.exchangeProto(proto, m)

		if err != nil && proto == "udp" && isTimeout(err) {
			// Don't make second try when UDP timed out
			// This means that either the upstream is not healthy,
			// or it simply can't resolve this DNS query.
			// Anyways, it makes no sense to retry.
			break
		}

		// If this was a cached connection, let's retry with a new one
		if err != nil && cached {
			continue
		}

		// If this is a truncated response, switch protocol to "tcp" and retry
		if err == nil && proto == "udp" && ret.Truncated {
			proto = "tcp"
			continue
		}

		break
	}

	RequestCount.WithLabelValues(p.addr).Add(1)
	RequestDuration.WithLabelValues(p.addr).Observe(time.Since(start).Seconds())

	if ret != nil {
		rc, ok := dns.RcodeToString[ret.Rcode]
		if !ok {
			rc = strconv.Itoa(ret.Rcode)
		}
		RcodeCount.WithLabelValues(rc, p.addr).Add(1)
	}

	if err != nil {
		ErrorsCount.WithLabelValues(p.addr).Add(1)
	}

	return ret, err
}

func (p *Proxy) Close() {
	p.udpConns.Close()
	p.tcpConns.Close()
}

// Sends a DNS query to the proxy and returns the response
// Returns:
// dns.Msg - response
// cached flag - if true, we used a cached connection
// error if any
func (p *Proxy) exchangeProto(proto string, m *dns.Msg) (*dns.Msg, bool, error) {
	var conn *Conn
	var cached bool
	var pool *connsPool

	if proto == "tcp" {
		pool = p.tcpConns
	} else {
		pool = p.udpConns
	}

	conn = pool.Get()
	if conn != nil && conn.IsExpired() {
		_ = conn.Close()
		conn = nil
	}

	if conn == nil {
		conn = &Conn{
			addr:  p.addr,
			proto: proto,
		}
	} else {
		cached = true
	}

	var bp *[]byte
	if proto == "tcp" {
		bp = p.tcpBuffs.Get().(*[]byte)
	} else {
		bp = p.udpBuffs.Get().(*[]byte)
	}

	ret, err := conn.Exchange(*bp, m)

	// Return resources to the pool
	if proto == "tcp" {
		// Suppress SA6002, it IS a pointer-like obj
		// nolint
		p.tcpBuffs.Put(bp)
	} else {
		// Suppress SA6002, it IS a pointer-like obj
		// nolint
		p.udpBuffs.Put(bp)
	}

	if err == nil {
		// Return connection to the pool only if the query was successful
		pool.Put(conn)
	} else {
		_ = conn.Close()
	}

	return ret, cached, err
}
