package querylog_test

import (
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/miekg/dns"
)

// testRequestID is the common request ID for tests.
var testRequestID = agd.NewRequestID()

// testEntry returns an entry for tests.
func testEntry() (e *querylog.Entry) {
	return &querylog.Entry{
		RequestResult: &filter.ResultBlocked{
			List: "adguard_dns_filter",
			Rule: "||example.com^",
		},
		ResponseResult:  nil,
		Time:            time.Unix(123, 0),
		RequestID:       testRequestID,
		ProfileID:       "prof1234",
		DeviceID:        "dev1234",
		ClientCountry:   geoip.CountryRU,
		ResponseCountry: geoip.CountryUS,
		DomainFQDN:      "example.com.",
		Protocol:        agd.ProtoDNS,
		ClientASN:       1234,
		Elapsed:         5 * time.Millisecond,
		RequestType:     dns.TypeA,
		ResponseCode:    dns.RcodeSuccess,
		DNSSEC:          true,
	}
}
