package querylog

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
)

// Entry is a single query log entry.
type Entry struct {
	// RemoteIP is the remote IP address of the client.
	RemoteIP netip.Addr

	// RequestResult is the result of filtering the DNS request.
	RequestResult filter.Result

	// ResponseResult is the result of filtering the DNS response.
	ResponseResult filter.Result

	// Time is the time of receiving the request.
	Time time.Time

	// ProfileID is the detected profile ID, if any.
	ProfileID agd.ProfileID

	// DeviceID is the detected device ID, if any.
	DeviceID agd.DeviceID

	// ClientCountry is the detected country of the client's IP address, if any.
	ClientCountry geoip.Country

	// ResponseCountry is the detected country of the first IP in the response
	// sent to the client, if any.
	ResponseCountry geoip.Country

	// DomainFQDN is the fully-qualified name of the requested resource.
	DomainFQDN string

	// RequestID is the ID of the request.
	//
	// TODO(a.garipov): Remove once not necessary anymore.
	RequestID agd.RequestID

	// Elapsed is the time passed since the beginning of the request processing.
	Elapsed time.Duration

	// ClientASN is the detected autonomous system number of the client's IP
	// address, if any.
	ClientASN geoip.ASN

	// RequestType is the type of the resource record of the query.
	RequestType dnsmsg.RRType

	// ResponseCode is the response code sent to the client.
	ResponseCode dnsmsg.RCode

	// Protocol is the DNS protocol used.
	Protocol agd.Protocol

	// DNSSEC is set to true if the response was validated with DNSSEC.
	DNSSEC bool
}

// resultCode is the code that identifies the code of actions performed for
// a single DNS query for logging etc.
type resultCode uint8

// Result code values.
const (
	// NOTE: DO NOT change the numerical values or use iota, because other
	// packages and modules may depend on the numerical values.  These numerical
	// values are a part of the API.

	resultCodeInvalid     resultCode = 0
	resultCodeNone        resultCode = 1
	resultCodeReqBlocked  resultCode = 2
	resultCodeRespBlocked resultCode = 3
	resultCodeReqAllowed  resultCode = 4
	resultCodeRespAllowed resultCode = 5
	resultCodeModified    resultCode = 6
)

// resultData returns the resultCode, filter list ID, and filtering rule from
// the request and response filtering results.
func resultData(req, resp filter.Result) (c resultCode, id filter.ID, r filter.RuleText) {
	if req == nil {
		c = toResultCode(resp, true)
		if resp != nil {
			id, r = resp.MatchedRule()
		}

		return c, id, r
	}

	c = toResultCode(req, false)
	id, r = req.MatchedRule()

	return c, id, r
}

// toResultCode converts a filter.Result into a resultCode.  If resp is true,
// r is considered to be a result of filtering the response.
func toResultCode(r filter.Result, resp bool) (c resultCode) {
	switch r.(type) {
	case nil:
		return resultCodeNone
	case *filter.ResultAllowed:
		if resp {
			return resultCodeRespAllowed
		}

		return resultCodeReqAllowed
	case *filter.ResultBlocked:
		if resp {
			return resultCodeRespBlocked
		}

		return resultCodeReqBlocked
	case *filter.ResultModifiedResponse, *filter.ResultModifiedRequest:
		return resultCodeModified
	default:
		// Consider unhandled sum type members as unrecoverable programmer
		// errors.
		panic(&agd.ArgumentError{
			Name:    "r",
			Message: fmt.Sprintf("unexpected type %T", r),
		})
	}
}

// jsonlEntry is a single JSONL query log jsonlEntry / line.
type jsonlEntry struct {
	// RemoteIP is the remote IP address of the client.  This field is optional.
	//
	// The short name "ip" stands for "IP".
	//
	// TODO(d.kolyshev): Do not use pointer when `omitempty` is supported for
	// zero structs.  See https://github.com/golang/go/issues/11939.
	RemoteIP *netip.Addr `json:"ip,omitempty"`

	// RequestID is the ID of the request.
	//
	// The short name "u" stands for "unique".
	RequestID string `json:"u"`

	// ProfileID is the detected profile ID, if any.
	//
	// The short name "b" stands for "buyer".
	ProfileID agd.ProfileID `json:"b"`

	// DeviceID is the detected device ID, if any.
	//
	// The short name "i" stands for "ID".
	DeviceID agd.DeviceID `json:"i"`

	// ClientCountry is the detected country of the client's IP address, if any.
	//
	// The short name "c" stands for "client country".
	ClientCountry geoip.Country `json:"c,omitempty"`

	// ResponseCountry is the detected country of the first IP in the response
	// sent to the client, if any.
	//
	// The short name "d" stands for "direction" or "destination".
	ResponseCountry geoip.Country `json:"d,omitempty"`

	// DomainFQDN is the requested resource name.
	//
	// The short name "n" stands for "name".
	DomainFQDN string `json:"n"`

	// FilterListID is the ID of the first filter the rules of which matched.
	// If no rules matched, this field is omitted.
	//
	// If the entry is matched by a blocked service, FilterListID is set to
	// [filter.IDBlockedService].  In case of a category filter, FilterListID
	// is set to [filter.IDCategory].
	//
	// The short name "l" stands for "list of filter rules".
	FilterListID filter.ID `json:"l,omitempty"`

	// FilterRule is the reason why the request was filtered.  It is the text of
	// the rule that matched the request, or the ID of the blocked service, or
	// the ID of the category.  If no rules matched, this field is
	// omitted.
	//
	// The short name "m" stands for "match".
	FilterRule filter.RuleText `json:"m,omitempty"`

	// Timestamp is the Unix time of receiving the request in milliseconds.
	//
	// The short name "t" stands for "time".
	Timestamp int64 `json:"t"`

	// ClientASN is the detected autonomous system number of the client's IP
	// address, if any.
	//
	// The short name "a" stands for "ASN".
	ClientASN geoip.ASN `json:"a,omitempty"`

	// Elapsed is the time passed since the beginning of the request processing
	// in milliseconds.
	//
	// The short name "e" stands for "elapsed".
	Elapsed uint32 `json:"e"`

	// RequestType is the type of the resource record of the query.
	//
	// The short name "q" stands for "question".
	RequestType dnsmsg.RRType `json:"q"`

	// ResponseCode is the response code sent to the client.
	//
	// The short name "r" stands for "response".
	ResponseCode dnsmsg.RCode `json:"r"`

	// Random is a random number added to an entry for easier deduplication.
	//
	// The short name "rn" stands for "random number".
	Random uint16 `json:"rn"`

	// ResultCode is the action taken with this request.
	//
	// The short name "f" stands for "filtering".
	ResultCode resultCode `json:"f"`

	// DNSSEC is 1 if the response was validated with DNSSEC and 0 otherwise.
	// It is a number and not a boolean to save space in the resulting JSON
	// object.
	//
	// The short name "s" stands for "secure".
	DNSSEC uint8 `json:"s"`

	// Protocol is the DNS protocol used.
	//
	// The short name "p" stands for "protocol".
	Protocol agd.Protocol `json:"p"`
}
