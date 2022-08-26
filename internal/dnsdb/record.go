package dnsdb

import (
	"bytes"
	"encoding/gob"
	"strconv"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/miekg/dns"
)

// DNSDB Records

// record is a single DNSDB record as it is stored in the BoldDB database.
//
// DO NOT change the names of the fields, since gob is used to encode it.
type record struct {
	// DomainName is the question FQDN from the request.
	DomainName string

	// Answer is either the IP address (for A and AAAA responses) or the
	// hostname (for CNAME responses).
	//
	// If there are no answers, this field is empty.
	Answer string

	// Hits shows how many times this domain was requested.  All records with
	// the same DomainName share this value.
	Hits uint64

	// RRType is the resource record type of the answer.  Currently, only A,
	// AAAA, and CNAME responses are recorded.
	//
	// If there are no answers, RRType is the type of the resource record type
	// of the question instead.
	RRType dnsmsg.RRType

	// RCode is the response code.  Currently we only record successful queries,
	// but that may change if the future.
	RCode dnsmsg.RCode
}

// csv returns CSV fields containing the record's information in the predefined
// order.
func (r *record) csv() (fields []string) {
	// DO NOT change the order of fields, since other parts of the system depend
	// on it.
	return []string{
		r.DomainName,
		dns.TypeToString[r.RRType],
		dns.RcodeToString[int(r.RCode)],
		r.Answer,
		strconv.FormatUint(r.Hits, 10),
	}
}

// encode encodes a slice of DNSDB records using gob.
func encode(recs []*record) (b []byte, err error) {
	buf := &bytes.Buffer{}
	err = gob.NewEncoder(buf).Encode(recs)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// decode decodes a slice of DNSDB records from gob data.
func decode(b []byte) (recs []*record, err error) {
	r := bytes.NewReader(b)
	err = gob.NewDecoder(r).Decode(&recs)
	if err != nil {
		return nil, err
	}

	return recs, nil
}

// toDBRecords converts DNS query data into a slice of DNSDB records.
func toDBRecords(qt dnsmsg.RRType, name string, ans []dns.RR, rc dnsmsg.RCode) (recs []*record) {
	if len(ans) == 0 {
		return []*record{newDBRecord(qt, name, nil, rc)}
	}

	for _, rr := range ans {
		if isAcceptedRRType(rr) {
			recs = append(recs, newDBRecord(qt, name, rr, rc))
		}
	}

	return recs
}

// isAcceptedRRType returns true if rr has one of the accepted answer resource
// record types.
func isAcceptedRRType(rr dns.RR) (ok bool) {
	switch rr.(type) {
	case *dns.A, *dns.AAAA, *dns.CNAME:
		return true
	default:
		return false
	}
}

// newDBRecord converts the DNS message data to a DNSDB record.
func newDBRecord(qt dnsmsg.RRType, name string, rr dns.RR, rc dnsmsg.RCode) (rec *record) {
	rec = &record{
		DomainName: name,
		Hits:       1,
		RCode:      rc,
	}

	if rr == nil {
		rec.RRType = qt

		return rec
	}

	rec.RRType = rr.Header().Rrtype

	switch v := rr.(type) {
	case *dns.A:
		rec.Answer = v.A.String()
	case *dns.AAAA:
		rec.Answer = v.AAAA.String()
	case *dns.CNAME:
		rec.Answer = strings.TrimSuffix(v.Target, ".")
	}

	return rec
}
