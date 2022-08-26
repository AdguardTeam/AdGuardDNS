package dnsserver

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// JSONMsg represents a *dns.Msg in the JSON format defined here:
// https://developers.google.com/speed/public-dns/docs/doh/json#dns_response_in_json
// Note, that we do not implement some parts of it. There is no "Comment" field
// and there's no "edns_client_subnet".
type JSONMsg struct {
	Question           []JSONQuestion `json:"Question"`
	Answer             []JSONAnswer   `json:"Answer"`
	Extra              []JSONAnswer   `json:"Extra"`
	Truncated          bool           `json:"TC"`
	RecursionDesired   bool           `json:"RD"`
	RecursionAvailable bool           `json:"RA"`
	AuthenticatedData  bool           `json:"AD"`
	CheckingDisabled   bool           `json:"CD"`
	Status             int            `json:"Status"`
}

// JSONQuestion is a part of JSONMsg definition.
type JSONQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// JSONAnswer is a part of JSONMsg definition.
type JSONAnswer struct {
	Name  string `json:"name"`
	Data  string `json:"data"`
	TTL   uint32 `json:"TTL"`
	Type  uint16 `json:"type"`
	Class uint16 `json:"class"`
}

// DNSMsgToJSONMsg converts the *dns.Msg to the JSON format (*JSONMsg).
func DNSMsgToJSONMsg(m *dns.Msg) (msg *JSONMsg) {
	msg = &JSONMsg{
		Status:             m.Rcode,
		Truncated:          m.Truncated,
		RecursionDesired:   m.RecursionDesired,
		RecursionAvailable: m.RecursionAvailable,
		AuthenticatedData:  m.AuthenticatedData,
		CheckingDisabled:   m.CheckingDisabled,
	}

	for _, q := range m.Question {
		msg.Question = append(msg.Question, JSONQuestion{
			Name: q.Name,
			Type: q.Qtype,
		})
	}

	for _, rr := range m.Answer {
		msg.Answer = append(msg.Answer, rrToJSON(rr))
	}

	for _, rr := range m.Extra {
		msg.Extra = append(msg.Extra, rrToJSON(rr))
	}

	return msg
}

// rrToJSON converts the specified rr to JSONAnswer.
func rrToJSON(rr dns.RR) (j JSONAnswer) {
	hdr := rr.Header()

	// Extracting the RR value is a bit tricky since miekg/dns does not
	// expose the necessary methods.  This way we can benefit from the
	// proper string serialization code that's used inside miekg/dns.
	hdrStr := hdr.String()
	valStr := rr.String()
	data := strings.TrimLeft(strings.TrimPrefix(valStr, hdrStr), " ")

	return JSONAnswer{
		Name:  hdr.Name,
		Type:  hdr.Rrtype,
		TTL:   hdr.Ttl,
		Class: hdr.Class,
		Data:  data,
	}
}

// dnsMsgToJSON converts the *dns.Msg to the JSON format (JSONMsg) and returns
// it in the serialized form.
func dnsMsgToJSON(m *dns.Msg) (b []byte, err error) {
	msg := DNSMsgToJSONMsg(m)
	return json.Marshal(msg)
}

// httpRequestToMsgJSON builds a DNS message from the request parameters.
// We use the same parameters as the ones defined here:
// https://developers.google.com/speed/public-dns/docs/doh/json#supported_parameters
// Some parameters are not supported: "ct", "edns_client_subnet".
func httpRequestToMsgJSON(req *http.Request) (b []byte, err error) {
	q := req.URL.Query()

	// Query name, the only required parameter.
	name := q.Get("name")
	if name == "" {
		// Indicate that the argument is invalid
		return nil, ErrInvalidArgument
	}

	// RR type can be represented as a number in [1, 65535] or a
	// canonical string (case-insensitive, such as A or AAAA).
	var t uint16
	t, err = urlQueryParameterToUint16(q, "type", dns.TypeA, dns.StringToType)
	if err != nil {
		return nil, err
	}

	// Query class can be represented as a number in [1, 65535] or a
	// canonical string (case-insensitive).
	var qc uint16
	qc, err = urlQueryParameterToUint16(q, "qc", dns.ClassINET, dns.StringToClass)
	if err != nil {
		return nil, err
	}

	// The CD (Checking Disabled) flag. Use cd=1, or cd=true to disable
	// DNSSEC validation; use cd=0, cd=false, or no cd parameter to
	// enable DNSSEC validation.
	var cd bool
	cd, err = urlQueryParameterToBoolean(q, "cd", false)
	if err != nil {
		return nil, err
	}

	// The DO (DNSSEC OK) flag. Use do=1, or do=true to include DNSSEC
	// records (RRSIG, NSEC, NSEC3); use do=0, do=false, or no do parameter
	// to omit DNSSEC records.
	var do bool
	do, err = urlQueryParameterToBoolean(q, "do", false)
	if err != nil {
		return nil, err
	}

	// Now build a DNS message with all those parameters
	r := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:               dns.Id(),
			CheckingDisabled: cd,
			RecursionDesired: true,
		},
		Question: []dns.Question{
			{
				Name:   dns.Fqdn(name),
				Qtype:  t,
				Qclass: qc,
			},
		},
	}

	if do {
		r.SetEdns0(dns.MaxMsgSize, do)
	}

	return r.Pack()
}

// urlQueryParameterToUint16 is a helper function that extracts a uint16 value
// from a query parameter. See httpRequestToMsgJSON to see how it's used.
func urlQueryParameterToUint16(
	q url.Values,
	name string,
	defaultValue uint16,
	strValuesMap map[string]uint16,
) (v uint16, err error) {
	strValue := q.Get(name)
	uintValue, convErr := strconv.ParseUint(strValue, 10, 16)
	switch {
	case strValue == "":
		// use default value if nothing was specified.
		v = defaultValue
	case convErr == nil:
		// use the specified value if it is a valid uint16.
		v = uint16(uintValue)
	default:
		// check if the specified string value is in the lookup map.
		var ok bool
		v, ok = strValuesMap[strings.ToUpper(strValue)]
		if !ok {
			// specified type is invalid.
			return 0, ErrInvalidArgument
		}
	}

	return v, nil
}

// urlQueryParameterToBoolean is a helper function that extracts a boolean value
// from a query parameter. See httpRequestToMsgJSON to see how it's used.
func urlQueryParameterToBoolean(
	q url.Values,
	name string,
	defaultValue bool,
) (v bool, err error) {
	strValue := q.Get(name)
	switch strValue {
	case "1", "true", "True":
		v = true
	case "0", "false", "False":
		v = false
	case "":
		v = defaultValue
	default:
		return defaultValue, ErrInvalidArgument
	}

	return v, nil
}
