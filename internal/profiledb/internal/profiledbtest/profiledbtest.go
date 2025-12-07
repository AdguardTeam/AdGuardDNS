// Package profiledbtest contains common helpers for profile-database tests.
package profiledbtest

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/require"
)

// AccountID is the profile ID for tests.
const AccountID agd.AccountID = "acc1234"

// ProfileID is the profile ID for tests.
const ProfileID agd.ProfileID = "prof1234"

// Device IDs for tests.
const (
	DeviceID     agd.DeviceID = "dev1234"
	DeviceIDAuto agd.DeviceID = "auto1234"
)

// HumanID values for tests.
const (
	HumanID      agd.HumanID      = "My-Device-X--10"
	HumanIDLower agd.HumanIDLower = "my-device-x--10"
)

// RespSzEst is a response-size estimate for tests.
const RespSzEst datasize.ByteSize = 1 * datasize.KB

// Timeout is the common timeout for tests.
const Timeout = 1 * time.Second

// WellKnownPath is the well-known certificate validation path for tests.
const WellKnownPath = "/.well-known/pki-validation/abcd1234"

// Logger is the common logger for tests.
var Logger = slogutil.NewDiscardLogger()

var (
	// IPv4 is a common IPv4 address for tests.
	IPv4 = netip.MustParseAddr("192.0.2.0")

	// IPv6 is a common IPv6 address for tests.
	IPv6 = netip.MustParseAddr("2001:db8::")

	// IPv4Bytes is a common binary marshalled IPv4 address for tests.
	IPv4Bytes = errors.Must(IPv4.MarshalBinary())

	// IPv6Bytes is a common binary marshalled IPv6 address for tests.
	IPv6Bytes = errors.Must(IPv6.MarshalBinary())

	// IPv4Prefix is a common IPv4 prefix for tests.
	IPv4Prefix = netip.PrefixFrom(IPv4, 24)

	// IPv6Prefix is a common IPv6 prefix for tests.
	IPv6Prefix = netip.PrefixFrom(IPv6, 32)
)

// ProfileAccessConstructor is the common constructor of profile access managers
// for tests.
var ProfileAccessConstructor = access.NewProfileConstructor(&access.ProfileConstructorConfig{
	Metrics:  access.EmptyProfileMetrics{},
	Standard: access.EmptyProfile{},
})

// ContextWithTimeout is a helper that returns a context with [Timeout].
func ContextWithTimeout(tb testing.TB) (ctx context.Context) {
	return testutil.ContextWithTimeout(tb, Timeout)
}

// NewDevice returns a new device with the given ID and name for tests.
func NewDevice(tb testing.TB, id agd.DeviceID, name agd.DeviceName) (d *agd.Device) {
	tb.Helper()

	return &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      true,
			DoHAuthOnly:  true,
			PasswordHash: agdpasswd.NewPasswordHashBcrypt([]byte("test")),
		},
		ID:       id,
		LinkedIP: netip.MustParseAddr("1.2.3.4"),
		Name:     name,
		DedicatedIPs: []netip.Addr{
			netip.MustParseAddr("1.2.4.5"),
		},
		FilteringEnabled: true,
	}
}

// NewProfile returns the common profile and device for tests.  The profile has
// ID [ProfileID] and the device, [DeviceID].  The response size estimate for
// the rate limiter is [RespSzEst].
func NewProfile(tb testing.TB) (p *agd.Profile, d *agd.Device) {
	tb.Helper()

	loc, err := agdtime.LoadLocation("Europe/Brussels")
	require.NoError(tb, err)

	const schedEnd = 701

	parental := &filter.ConfigParental{
		Categories: &filter.ConfigCategories{
			IDs:     []filter.CategoryID{"games"},
			Enabled: true,
		},
		PauseSchedule: &filter.ConfigSchedule{
			Week: &filter.WeeklySchedule{
				time.Monday:    {Start: 0, End: schedEnd},
				time.Tuesday:   {Start: 0, End: schedEnd},
				time.Wednesday: {Start: 0, End: schedEnd},
				time.Thursday:  {Start: 0, End: schedEnd},
				time.Friday:    {Start: 0, End: schedEnd},
				time.Saturday:  nil,
				time.Sunday:    nil,
			},
			TimeZone: loc,
		},
		Enabled: true,
	}

	customDomains := &agd.AccountCustomDomains{
		Domains: []*agd.CustomDomainConfig{{
			State: &agd.CustomDomainStateCurrent{
				CertName:  "abcdefgh",
				NotBefore: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC),
				NotAfter:  time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
				Enabled:   true,
			},
			Domains: []string{
				"current-1.domain.example",
				"current-2.domain.example",
			},
		}, {
			State: &agd.CustomDomainStatePending{
				WellKnownPath: WellKnownPath,
				Expire:        time.Date(2022, 1, 1, 0, 0, 0, 0, time.UTC),
			},
			Domains: []string{
				"pending-1.domain.example",
				"pending-2.domain.example",
			},
		}},
		Enabled: true,
	}

	customFltConf := &custom.Config{
		Logger: Logger,
		Rules:  []filter.RuleText{"|blocked-by-custom.example^"},
	}

	dev := NewDevice(tb, DeviceID, "dev1")

	return &agd.Profile{
		CustomDomains: customDomains,
		FilterConfig: &filter.ConfigClient{
			Custom: &filter.ConfigCustom{
				Filter:  custom.New(customFltConf),
				Enabled: true,
			},
			Parental: parental,
			RuleList: &filter.ConfigRuleList{
				IDs:     []filter.ID{filter.IDAdGuardDNS},
				Enabled: true,
			},
			SafeBrowsing: &filter.ConfigSafeBrowsing{
				Enabled:                       true,
				DangerousDomainsEnabled:       true,
				NewlyRegisteredDomainsEnabled: false,
			},
		},
		Access: ProfileAccessConstructor.New(&access.ProfileConfig{
			AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
			BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
			AllowedASN:           []geoip.ASN{1},
			BlockedASN:           []geoip.ASN{2},
			BlocklistDomainRules: []string{"block.test"},
			StandardEnabled:      true,
		}),
		AdultBlockingMode:        &dnsmsg.BlockingModeNullIP{},
		BlockingMode:             &dnsmsg.BlockingModeNullIP{},
		SafeBrowsingBlockingMode: &dnsmsg.BlockingModeNullIP{},
		Ratelimiter: agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
			ClientSubnets: []netip.Prefix{netip.MustParsePrefix("5.5.5.0/24")},
			RPS:           100,
			Enabled:       true,
		}, RespSzEst),
		AccountID:           AccountID,
		ID:                  ProfileID,
		DeviceIDs:           container.NewMapSet(dev.ID),
		FilteredResponseTTL: 10 * time.Second,
		AutoDevicesEnabled:  true,
		BlockChromePrefetch: true,
		BlockFirefoxCanary:  true,
		BlockPrivateRelay:   true,
		Deleted:             false,
		FilteringEnabled:    true,
		IPLogEnabled:        true,
		QueryLogEnabled:     true,
	}, dev
}
