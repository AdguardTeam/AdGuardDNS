package dnsserver

import (
	"encoding/binary"
	"fmt"
	"slices"

	"github.com/miekg/dns"
)

// genErrorResponse creates a short DNS message with the specified rcode.
// it is supposed to be used for generating errors (server failure, bad format,
// etc.)
func genErrorResponse(req *dns.Msg, code int) (m *dns.Msg) {
	m = &dns.Msg{}
	m.SetRcode(req, code)

	return m
}

// questionData extracts DNS Question data in a safe manner.
func questionData(m *dns.Msg) (hostname, qType string) {
	if len(m.Question) > 0 {
		q := m.Question[0]
		hostname = q.Name
		if v, ok := dns.TypeToString[q.Qtype]; ok {
			qType = v
		} else {
			qType = fmt.Sprintf("TYPE%d", q.Qtype)
		}
	}

	return hostname, qType
}

// packWithPrefix packs a DNS message with a 2-byte prefix with the message
// length by appending it into buf and returns it.
func packWithPrefix(m *dns.Msg, buf []byte) (packed []byte, err error) {
	buf, err = m.PackBuffer(buf)
	if err != nil {
		return nil, err
	}

	// Try to reuse the slice if there is already space there.
	packed = slices.Grow(buf, 2)[:len(buf)+2]

	copy(packed[2:], buf)
	binary.BigEndian.PutUint16(packed[:2], uint16(len(buf)))

	return packed, nil
}
