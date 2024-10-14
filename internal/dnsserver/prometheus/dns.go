package prometheus

import (
	"strconv"

	"github.com/miekg/dns"
)

// typeToString converts query type to a human-readable string.
func typeToString(req *dns.Msg) string {
	var qType uint16
	if len(req.Question) == 1 {
		// NOTE: req can be invalid here, so check if the question is okay.
		qType = req.Question[0].Qtype
	}

	switch qType {
	case
		dns.TypeA,
		dns.TypeAAAA,
		dns.TypeCNAME,
		dns.TypeDNSKEY,
		dns.TypeDS,
		dns.TypeHTTPS,
		dns.TypeMX,
		dns.TypeNS,
		dns.TypeNSEC,
		dns.TypeNSEC3,
		dns.TypePTR,
		dns.TypeRRSIG,
		dns.TypeSOA,
		dns.TypeSRV,
		dns.TypeSVCB,
		dns.TypeTXT,
		// Meta Qtypes:
		dns.TypeANY,
		dns.TypeAXFR,
		dns.TypeIXFR:
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
