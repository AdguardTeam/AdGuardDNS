// Package profiledbtest contains common helpers for profile-database tests.
package profiledbtest

import (
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
	"github.com/AdguardTeam/golibs/logutil/slogutil"
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

// WellKnownPath is the well-known certificate validation path for tests.
const WellKnownPath = "/.well-known/pki-validation/abcd1234"

// NewProfile returns the common profile and device for tests.  The profile has
// ID [ProfileID] and the device, [DeviceID].  The response size estimate for
// the rate limiter is [RespSzEst].
func NewProfile(tb testing.TB) (p *agd.Profile, d *agd.Device) {
	tb.Helper()

	loc, err := agdtime.LoadLocation("Europe/Brussels")
	require.NoError(tb, err)

	dev := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      true,
			DoHAuthOnly:  true,
			PasswordHash: agdpasswd.NewPasswordHashBcrypt([]byte("test")),
		},
		ID:       DeviceID,
		LinkedIP: netip.MustParseAddr("1.2.3.4"),
		Name:     "dev1",
		DedicatedIPs: []netip.Addr{
			netip.MustParseAddr("1.2.4.5"),
		},
		FilteringEnabled: true,
	}

	const schedEnd = 701

	parental := &filter.ConfigParental{
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
		Logger: slogutil.NewDiscardLogger(),
		Rules:  []filter.RuleText{"|blocked-by-custom.example^"},
	}

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
		Access: access.NewDefaultProfile(&access.ProfileConfig{
			AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
			BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
			AllowedASN:           []geoip.ASN{1},
			BlockedASN:           []geoip.ASN{2},
			BlocklistDomainRules: []string{"block.test"},
		}),
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
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
