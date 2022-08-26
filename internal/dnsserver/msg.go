package dnsserver

import (
	"encoding/binary"
	"fmt"

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
// length.
func packWithPrefix(m *dns.Msg) (b []byte, err error) {
	var data []byte
	data, err = m.Pack()
	if err != nil {
		return nil, err
	}

	msg := make([]byte, 2+len(data))

	// *dns.Msg.Pack guarantees that data is less or equal to math.MaxUint16.
	binary.BigEndian.PutUint16(msg, uint16(len(data)))
	copy(msg[2:], data)
	return msg, nil
}
