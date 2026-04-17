// Package backendtest contains common helpers for the buisiness-logic backend
// tests.
//
// TODO(a.garipov):  Use test IP addresses and networks everywhere.
package backendtest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/require"
)

// ResponseSizeEstimate is a response-size estimate for tests.
const ResponseSizeEstimate datasize.ByteSize = 1 * datasize.KB

// Common IDs for tests and their string forms.
const (
	DeviceIDStr     = "dev1234"
	HumanIDStr      = "My-Device-X--10"
	HumanIDLowerStr = "my-device-x--10"
	ProfileIDStr    = "prof1234"

	AccountID    agd.AccountID    = 1234
	DeviceID     agd.DeviceID     = DeviceIDStr
	HumanID      agd.HumanID      = HumanIDStr
	HumanIDLower agd.HumanIDLower = HumanIDLowerStr
	ProfileID    agd.ProfileID    = ProfileIDStr
)

// BlocklistDomainRule is a common domain rule for tests.
const BlocklistDomainRule = "rule"

// Common ASNs for tests.
const (
	ASNAllowed = 12345
	ASNBlocked = 12346
)

// Common domains for tests.
const (
	ETLDPlus1    = "protected.example"
	ETLDPlus1Exc = "protectedx.example"
)

// Timeout is the common timeout for tests.
const Timeout = 1 * time.Second

// Common time values for tests.
var (
	// TimeNotBefore is the common not-before time for tests.
	TimeNotBefore = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

	// TimeNotAfter is the common not-after time for tests.
	TimeNotAfter = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

	// TimePendingExpire is the common pending-cert expire-time for tests.
	TimePendingExpire = time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC)

	// TimeSync is the common update time for tests.
	TimeSync = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
)

// Bind includes any IPv4 address.
//
// TODO(a.garipov):  Add to golibs/netutil.
var Bind = netip.MustParsePrefix("0.0.0.0/0")

// Logger is the common logger for tests.
var Logger = slogutil.NewDiscardLogger()

// ErrColl is the common error collector for tests.
var ErrColl = agdtest.NewErrorCollector()

// ProfileAccessConstructor is the common constructor of profile access managers
// for tests
var ProfileAccessConstructor = access.NewProfileConstructor(&access.ProfileConstructorConfig{
	Metrics:  access.EmptyProfileMetrics{},
	Standard: access.EmptyBlocker{},
})

// Common typosquatting-filter index for tests.
var (
	TyposquattingIndexGRPC = &dnspb.TyposquattingFilterIndex{
		Domains: []*dnspb.TyposquattingFilterIndex_ProtectedDomain{{
			Domain:   ETLDPlus1,
			Distance: 1,
		}},
		Exceptions: []*dnspb.TyposquattingFilterIndex_Exception{{
			Domain: ETLDPlus1Exc,
		}},
	}

	TyposquattingIndex = &filterindex.Typosquatting{
		Domains: []*filterindex.TyposquattingProtectedDomain{{
			Domain:   ETLDPlus1,
			Distance: 1,
		}},
		Exceptions: []*filterindex.TyposquattingException{{
			Domain: ETLDPlus1Exc,
		}},
	}
)

// IPStringToBytes converts s to netip.Addr and then calls
// [netip.Addr.MarshalBinary].
func IPStringToBytes(tb testing.TB, s string) (b []byte) {
	tb.Helper()

	ip, err := netip.ParseAddr(s)
	require.NoError(tb, err)

	b, err = ip.MarshalBinary()
	require.NoError(tb, err)

	return b
}
