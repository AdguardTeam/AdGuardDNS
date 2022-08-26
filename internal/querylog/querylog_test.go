package querylog_test

import (
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/querylog"
	"github.com/miekg/dns"
)

func TestMain(m *testing.M) {
	agdtest.DiscardLogOutput(m)
}

// Helpers

// testEntry returns an entry for tests.
func testEntry() (e *querylog.Entry) {
	return &querylog.Entry{
		RequestResult: &filter.ResultBlocked{
			List: "adguard_dns_filter",
			Rule: "||example.com^",
		},
		ResponseResult:  nil,
		Time:            time.Unix(123, 0),
		RequestID:       "req1234",
		ProfileID:       "prof1234",
		DeviceID:        "dev1234",
		ClientCountry:   agd.CountryRU,
		ResponseCountry: agd.CountryUS,
		DomainFQDN:      "example.com.",
		Protocol:        agd.ProtoDNSUDP,
		ClientASN:       1234,
		Elapsed:         5,
		RequestType:     dns.TypeA,
		DNSSEC:          true,
		ResponseCode:    dns.RcodeSuccess,
	}
}
