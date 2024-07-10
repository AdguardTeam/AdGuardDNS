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
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/stretchr/testify/require"
)

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

// NewProfile returns the common profile and device for tests.
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

	return &agd.Profile{
		Parental: &agd.ParentalProtectionSettings{
			Schedule: &agd.ParentalProtectionSchedule{
				Week: &agd.WeeklySchedule{
					{Start: 0, End: 700},
					{Start: 0, End: 700},
					{Start: 0, End: 700},
					{Start: 0, End: 700},
					{Start: 0, End: 700},
					{Start: 0, End: 700},
					{Start: 0, End: 700},
				},
				TimeZone: loc,
			},
			Enabled: true,
		},
		BlockingMode: &dnsmsg.BlockingModeNullIP{},
		ID:           ProfileID,
		DeviceIDs:    []agd.DeviceID{dev.ID},
		RuleListIDs: []agd.FilterListID{
			"adguard_dns_filter",
		},
		CustomRules: []agd.FilterRuleText{
			"|blocked-by-custom.example",
		},
		FilteredResponseTTL: 10 * time.Second,
		FilteringEnabled:    true,
		SafeBrowsing: &agd.SafeBrowsingSettings{
			Enabled:                     true,
			BlockDangerousDomains:       true,
			BlockNewlyRegisteredDomains: false,
		},
		Access: access.NewDefaultProfile(&access.ProfileConfig{
			AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
			BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
			AllowedASN:           []geoip.ASN{1},
			BlockedASN:           []geoip.ASN{2},
			BlocklistDomainRules: []string{"block.test"},
		}),
		RuleListsEnabled:   true,
		QueryLogEnabled:    true,
		BlockPrivateRelay:  true,
		BlockFirefoxCanary: true,
		IPLogEnabled:       true,
		AutoDevicesEnabled: true,
	}, dev
}
