package backendtest

import (
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// NewDNSProfile returns a new instance of *DNSProfile for tests.  Keep in sync
// with [dnspb_test.newProfile].
func NewDNSProfile(tb testing.TB) (p *dnspb.DNSProfile) {
	tb.Helper()

	dayRanges := []*dnspb.DayRange{{
		Start: durationpb.New(0),
		End:   durationpb.New(59 * time.Minute),
	}, {
		Start: durationpb.New(12 * time.Hour),
		End:   durationpb.New(12*time.Hour + 59*time.Minute),
	}}

	week := &dnspb.WeeklyRanges{
		Sun: nil,
		Mon: dayRanges,
		Tue: dayRanges,
		Wed: dayRanges,
		Thu: dayRanges,
		Fri: dayRanges,
		Sat: nil,
	}

	customDomain := newCustomDomain()

	accountIP := &dnspb.AccountIPSettings{
		Enabled: true,
		Ips: []*dnspb.AccountIPSettings_IP{{
			Enabled: true,
			Ip:      []byte{192, 0, 2, 0},
			Domain: &dnspb.AccountIPSettings_DomainSettings{
				Domains: customDomain.Domains,
			},
		}},
	}

	return &dnspb.DNSProfile{
		DnsId:            ProfileIDStr,
		FilteringEnabled: true,
		QueryLogEnabled:  true,
		Deleted:          false,
		SafeBrowsing: &dnspb.SafeBrowsingSettings{
			Homoglyph: &dnspb.HomoglyphFilterSettings{
				Enabled: true,
			},
			Typosquatting: &dnspb.TyposquattingFilterSettings{
				Enabled: true,
			},
			Enabled:               true,
			BlockDangerousDomains: true,
			BlockNrd:              false,
		},
		Parental: &dnspb.ParentalSettings{
			Enabled:           false,
			BlockAdult:        false,
			GeneralSafeSearch: false,
			YoutubeSafeSearch: false,
			BlockedServices:   []string{"youtube"},
			Schedule: &dnspb.ScheduleSettings{
				Tmz:          "GMT",
				WeeklyRanges: week,
			},
		},
		CustomRuleLists: &dnspb.CustomRuleListsSettings{
			Enabled: true,
			Ids:     []string{"1"},
		},
		RuleLists: &dnspb.RuleListsSettings{
			Enabled: true,
			Ids:     []string{"2"},
		},
		Devices:             newDevices(tb),
		CustomRules:         []string{"||example.org^"},
		FilteredResponseTtl: durationpb.New(10 * time.Second),
		BlockPrivateRelay:   true,
		BlockFirefoxCanary:  true,
		IpLogEnabled:        true,
		AutoDevicesEnabled:  true,
		BlockingMode: &dnspb.DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: IPStringToBytes(tb, "1.2.3.4"),
				Ipv6: IPStringToBytes(tb, "1234::cdef"),
			},
		},
		AdultBlockingMode: &dnspb.DNSProfile_AdultBlockingModeCustomIp{
			AdultBlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: IPStringToBytes(tb, "1.1.1.1"),
				Ipv6: IPStringToBytes(tb, "1111::cdef"),
			},
		},
		SafeBrowsingBlockingMode: &dnspb.DNSProfile_SafeBrowsingBlockingModeCustomIp{
			SafeBrowsingBlockingModeCustomIp: &dnspb.BlockingModeCustomIP{
				Ipv4: IPStringToBytes(tb, "2.2.2.2"),
				Ipv6: IPStringToBytes(tb, "2222::cdef"),
			},
		},
		Access: &dnspb.AccessSettings{
			AllowlistCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("1.1.1.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("2.2.2.0").AsSlice(),
				Prefix:  24,
			}},
			AllowlistAsn:         []uint32{1},
			BlocklistAsn:         []uint32{2},
			BlocklistDomainRules: []string{"block.test"},
			Enabled:              true,
		},
		RateLimit: &dnspb.RateLimitSettings{
			Enabled: true,
			Rps:     100,
			ClientCidr: []*dnspb.CidrRange{{
				Address: netip.MustParseAddr("5.5.5.0").AsSlice(),
				Prefix:  24,
			}},
		},
		BlockChromePrefetch: true,
		CustomDomain:        newCustomDomain(),
		AccountIp:           accountIP,
		CategoryFilter: &dnspb.CategoryFilterSettings{
			Ids:     []string{"games"},
			Enabled: true,
		},
		AccountIdInt: int32(AccountID),
	}
}

// newDevices returns devices for tests.
func newDevices(tb testing.TB) (devices []*dnspb.DeviceSettings) {
	return []*dnspb.DeviceSettings{{
		Id:               DeviceIDStr,
		Name:             "1111aaaa-name",
		FilteringEnabled: false,
		LinkedIp:         IPStringToBytes(tb, "1.1.1.1"),
		DedicatedIps:     [][]byte{IPStringToBytes(tb, "1.1.1.2")},
	}, {
		Id:               "2222bbbb",
		Name:             "2222bbbb-name",
		FilteringEnabled: true,
		LinkedIp:         IPStringToBytes(tb, "2.2.2.2"),
		DedicatedIps:     nil,
		Authentication: &dnspb.AuthenticationSettings{
			DohAuthOnly: true,
			DohPasswordHash: &dnspb.AuthenticationSettings_PasswordHashBcrypt{
				PasswordHashBcrypt: []byte("test-hash"),
			},
		},
	}, {
		Id:               "3333cccc",
		Name:             "3333cccc-name",
		FilteringEnabled: false,
		LinkedIp:         IPStringToBytes(tb, "3.3.3.3"),
		DedicatedIps:     nil,
		Authentication: &dnspb.AuthenticationSettings{
			DohAuthOnly:     false,
			DohPasswordHash: nil,
		},
	}, {
		Id:               "4444dddd",
		Name:             "My Auto-Device",
		HumanIdLower:     "my-auto--device",
		FilteringEnabled: true,
	}}
}

// newCustomDomain returns custom-domain settings for tests.
func newCustomDomain() (s *dnspb.CustomDomainSettings) {
	customDomainPending := &dnspb.CustomDomain{
		Domains: []string{
			"pending-1.domain.example",
			"pending-2.domain.example",
		},
		State: &dnspb.CustomDomain_Pending_{
			Pending: &dnspb.CustomDomain_Pending{
				WellKnownPath: "/.well-known/abc/def",
				Expire:        timestamppb.New(TimePendingExpire),
			},
		},
	}

	customDomainCurrent := &dnspb.CustomDomain{
		Domains: []string{
			"current-1.domain.example",
			"current-2.domain.example",
		},
		State: &dnspb.CustomDomain_Current_{
			Current: &dnspb.CustomDomain_Current{
				CertName:  "abcdefgh",
				NotBefore: timestamppb.New(TimeNotBefore),
				NotAfter:  timestamppb.New(TimeNotAfter),
				Enabled:   true,
			},
		},
	}

	return &dnspb.CustomDomainSettings{
		Domains: []*dnspb.CustomDomain{
			customDomainCurrent,
			customDomainPending,
		},
		Enabled: true,
	}
}
