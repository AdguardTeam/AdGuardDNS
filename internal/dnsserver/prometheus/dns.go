package prometheus

import (
	"strconv"

	"github.com/miekg/dns"
)

/*
We keep different helpers for working with DNS messages here.
*/

// typeToString converts query type to a human-readable string.
func typeToString(req *dns.Msg) string {
	var qType uint16
	if len(req.Question) == 1 {
		// Note that we can receive invalid request here
		// so we should check if the question is okay.
		qType = req.Question[0].Qtype
	}

	switch qType {
	case dns.TypeAAAA,
		dns.TypeA,
		dns.TypeHTTPS,
		dns.TypeCNAME,
		dns.TypeDNSKEY,
		dns.TypeDS,
		dns.TypeMX,
		dns.TypeNSEC3,
		dns.TypeNSEC,
		dns.TypeNS,
		dns.TypePTR,
		dns.TypeRRSIG,
		dns.TypeSOA,
		dns.TypeSRV,
		dns.TypeTXT,
		// Meta Qtypes
		dns.TypeIXFR,
		dns.TypeAXFR,
		dns.TypeANY:
		return dns.Type(qType).String()
	}

	// Sometimes people prefer to log something like "TYPE{qtype}".  However,
	// practice shows that this creates quite a huge cardinality.
	return "OTHER"
}

// rCodeToString converts response code to a human-readable string.
func rCodeToString(rCode int) string {
	rc, ok := dns.RcodeToString[rCode]
	if !ok {
		rc = strconv.Itoa(rCode)
	}

	return rc
}
