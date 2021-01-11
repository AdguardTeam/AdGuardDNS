package upstream

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/miekg/dns"
)

const (
	// Connect timeout must be really short as this plugin is supposed
	// to be used with local upstreams mostly
	connectTimeout = 1 * time.Second

	// If connection was idle for this time, consider it dead
	idleTimeout = 30 * time.Second

	// Some resolves might take quite a while, usually (cached) responses are fast. Set to 2s to give us some time to retry a different upstream.
	readTimeout       = 2 * time.Second
	minDNSMessageSize = 12 + 5
)

// Conn - represents a persistent connection
type Conn struct {
	addr         string   // server address (IP:port)
	proto        string   // protocol ("tcp" or "udp")
	conn         net.Conn // underlying network connection
	lastTimeUsed time.Time
}

// ConnectOnce - connects to the "addr" using the specified "proto".
// If it's already connected, does nothing
func (c *Conn) ConnectOnce() error {
	if c.conn != nil {
		return nil
	}

	conn, err := net.DialTimeout(c.proto, c.addr, connectTimeout)
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

// Close - closes the underlying connection
func (c *Conn) Close() error {
	return c.conn.Close()
}

// IsExpired - checks if the connection was idle for too long
func (c *Conn) IsExpired() bool {
	return time.Now().After(c.lastTimeUsed.Add(idleTimeout))
}

// Exchange - sends the DNS query and returns the reply
// buf - buffer that this connection should use to read&write the DNS messages.
func (c *Conn) Exchange(buf []byte, m *dns.Msg) (*dns.Msg, error) {
	err := c.ConnectOnce()
	if err != nil {
		return nil, err
	}

	c.lastTimeUsed = time.Now()

	err = c.writeMsg(buf, m)
	if err != nil {
		return nil, err
	}

	ret, err := c.readMsg(buf)
	if err != nil {
		return nil, err
	}

	if m.Id != ret.Id {
		return nil, dns.ErrId
	}

	return ret, err
}

func (c *Conn) writeMsg(buf []byte, m *dns.Msg) error {
	b, err := m.PackBuffer(buf)
	if err != nil {
		return err
	}

	msgLen := m.Len()

	if c.proto == "tcp" {
		l := make([]byte, 2)
		binary.BigEndian.PutUint16(l, uint16(msgLen))
		_, err = (&net.Buffers{l, b[:msgLen]}).WriteTo(c.conn)
	} else {
		_, err = c.conn.Write(b)
	}

	return err
}

func (c *Conn) readMsg(buf []byte) (*dns.Msg, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(readTimeout))

	var err error
	var n int

	if c.proto == "tcp" {
		var length uint16
		if err = binary.Read(c.conn, binary.BigEndian, &length); err != nil {
			return nil, err
		}

		n, err = io.ReadFull(c.conn, buf[:length])
	} else {
		n, err = c.conn.Read(buf)
	}

	if err != nil {
		return nil, err
	}

	if n < minDNSMessageSize {
		return nil, dns.ErrShortRead
	}
	ret := new(dns.Msg)
	err = ret.Unpack(buf)
	if err != nil {
		return nil, err
	}
	return ret, nil
}
