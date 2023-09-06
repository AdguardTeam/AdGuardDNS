package dnsdb

import (
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

// record is a single DNSDB record as it is stored in the record's database.
type record struct {
	// target is the question target from the request.
	target string

	// answer is either the IP address (for A and AAAA responses) or the
	// hostname (for CNAME responses).
	//
	// If there are no answers, this field is empty.
	answer string

	// hits shows how many times this domain was requested.
	hits uint64

	// rrType is the resource record type of the answer.  Currently, only A,
	// AAAA, and CNAME responses are recorded.
	//
	// If there are no answers, rrType is the type of the resource record type
	// of the question instead.
	rrType dnsmsg.RRType

	// rcode is the response code.  Currently we only record successful queries,
	// but that may change if the future.
	rcode dnsmsg.RCode
}

// csv returns CSV fields containing the record's information in the predefined
// order.
func (r *record) csv() (fields []string) {
	// DO NOT change the order of fields, since other parts of the system depend
	// on it.
	return []string{
		r.target,
		dns.TypeToString[r.rrType],
		dns.RcodeToString[int(r.rcode)],
		r.answer,
		strconv.FormatUint(r.hits, 10),
	}
}

// answerString returns a string representation of an answer record.
func answerString(rr dns.RR) (s string) {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String()
	case *dns.AAAA:
		return v.AAAA.String()
	case *dns.CNAME:
		// TODO(a.garipov): Consider lowercasing target hostname.
		return strings.TrimSuffix(v.Target, ".")
	default:
		return ""
	}
}

// recordKey is the key a DNSDB entry.
type recordKey struct {
	target string
	qt     dnsmsg.RRType
}

// unit is a convenient alias for struct{}.
type unit = struct{}

// recordValue contains the values for a single record key.
type recordValue struct {
	answers map[recordAnswer]unit
	hits    uint64
}

// recordAnswer contains a single piece of the answer data.
type recordAnswer struct {
	value  string
	rrType dnsmsg.RRType
	rcode  dnsmsg.RCode
}
