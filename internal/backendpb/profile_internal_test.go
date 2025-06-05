package backendpb

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDNSProfile_ToInternal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	errColl := agdtest.NewErrorCollector()
	wantDevChg := &profiledb.StorageDeviceChange{}

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		got, gotDevices, gotDevChg, err := NewTestDNSProfile(t).toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
		assert.Equal(t, wantDevChg, gotDevChg)
	})

	t.Run("success_bad_data", func(t *testing.T) {
		t.Parallel()

		var errCollErr error
		savingErrColl := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errCollErr = err
			},
		}
		got, gotDevices, gotDevChg, err := newDNSProfileWithBadData(t).toInternal(
			ctx,
			TestLogger,
			savingErrColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(
			t,
			`converting device: bad settings for device with id "inv-d-ip":`+
				` dedicated ips: ip at index 0: unexpected slice size`,
			errCollErr,
		)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
		assert.Equal(t, wantDevChg, gotDevChg)
	})

	t.Run("invalid_device_ded_ip", func(t *testing.T) {
		t.Parallel()

		var errCollErr error
		savingErrColl := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errCollErr = err
			},
		}

		bindSet := netip.MustParsePrefix("2.2.2.2/32")
		got, gotDevices, gotDevChg, err := NewTestDNSProfile(t).toInternal(
			ctx,
			TestLogger,
			savingErrColl,
			bindSet,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(
			t,
			`converting device: bad settings for device with id "`+TestDeviceIDStr+`":`+
				" dedicated ips: at index 0: \"1.1.1.2\" is not in bind data",
			errCollErr,
		)

		assert.NotEqual(t, newProfile(t), got)
		assert.NotEqual(t, newDevices(t), gotDevices)
		assert.Len(t, gotDevices, 3)
		assert.Equal(t, wantDevChg, gotDevChg)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		var emptyDNSProfile *DNSProfile
		_, _, _, err := emptyDNSProfile.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(t, "profile is nil", err)
	})

	t.Run("deleted_profile", func(t *testing.T) {
		t.Parallel()

		dp := &DNSProfile{
			DnsId:   TestProfileIDStr,
			Deleted: true,
		}

		got, gotDevices, gotDevChg, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, TestProfileID)
		assert.True(t, got.Deleted)
		assert.Empty(t, gotDevices)
		assert.Equal(t, wantDevChg, gotDevChg)
	})

	t.Run("inv_parental_sch_tmz", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Parental.Schedule.Tmz = "invalid"

		_, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(
			t,
			"parental: pause schedule: loading timezone: unknown time zone invalid",
			err,
		)
	})

	t.Run("inv_parental_sch_day_range", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Parental.Schedule.WeeklyRange.Sun = &DayRange{
			Start: durationpb.New(1000000000000),
			End:   nil,
		}

		_, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(
			t,
			"parental: pause schedule: weekday Sunday: end: out of range: 1 is less than start 16",
			err,
		)
	})

	t.Run("inv_blocking_mode_v4", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv4 = []byte("1")

		_, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv4: unexpected slice size", err)
	})

	t.Run("inv_blocking_mode_v6", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv6 = []byte("1")

		_, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv6: unexpected slice size", err)
	})

	t.Run("nil_ips_blocking_mode", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv4 = nil
		bm.BlockingModeCustomIp.Ipv6 = nil

		_, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		testutil.AssertErrorMsg(t, "blocking mode: no valid custom ips found", err)
	})

	t.Run("nil_blocking_mode", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.BlockingMode = nil

		got, gotDevices, gotDevChg, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		wantProf := newProfile(t)
		wantProf.BlockingMode = &dnsmsg.BlockingModeNullIP{}

		assert.Equal(t, wantProf, got)
		assert.Equal(t, newDevices(t), gotDevices)
		assert.Equal(t, wantDevChg, gotDevChg)
	})

	t.Run("nil_access", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Access = nil

		got, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, TestProfileID)
		assert.IsType(t, access.EmptyProfile{}, got.Access)
	})

	t.Run("access_disabled", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Access = &AccessSettings{
			Enabled: false,
		}

		got, _, _, err := dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, TestProfileID)
		assert.IsType(t, access.EmptyProfile{}, got.Access)
	})
}

// newDNSProfileWithBadData returns a new instance of *DNSProfile with bad
// devices data for tests.
func newDNSProfileWithBadData(tb testing.TB) (dp *DNSProfile) {
	tb.Helper()

	invalidDevices := []*DeviceSettings{{
		Id:               "invalid-too-long-device-id",
		Name:             "device_name",
		FilteringEnabled: true,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("1.1.1.1")),
		DedicatedIps:     nil,
	}, {
		Id: "dev-name",
		Name: "invalid-too-long-device-name-invalid-too-long-device-name-" +
			"invalid-too-long-device-name-invalid-too-long-device-name-" +
			"invalid-too-long-device-name-invalid-too-long-device-name",
		FilteringEnabled: true,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("1.1.1.1")),
		DedicatedIps:     nil,
	}, {
		Id:               "inv-ip",
		Name:             "test-name",
		FilteringEnabled: true,
		LinkedIp:         []byte("1"),
		DedicatedIps:     nil,
	}, {
		Id:               "inv-d-ip",
		Name:             "test-name",
		FilteringEnabled: true,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("1.1.1.1")),
		DedicatedIps:     [][]byte{[]byte("1")},
	}}

	dp = NewTestDNSProfile(tb)
	dp.Devices = append(dp.Devices, invalidDevices...)

	return dp
}

// NewTestDNSProfile returns a new instance of *DNSProfile for tests.  Keep in
// sync with [newProfile].
func NewTestDNSProfile(tb testing.TB) (dp *DNSProfile) {
	tb.Helper()

	dayRange := &DayRange{
		Start: durationpb.New(0),
		End:   durationpb.New(59 * time.Minute),
	}

	devices := []*DeviceSettings{{
		Id:               TestDeviceIDStr,
		Name:             "1111aaaa-name",
		FilteringEnabled: false,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("1.1.1.1")),
		DedicatedIps:     [][]byte{ipToBytes(tb, netip.MustParseAddr("1.1.1.2"))},
	}, {
		Id:               "2222bbbb",
		Name:             "2222bbbb-name",
		FilteringEnabled: true,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("2.2.2.2")),
		DedicatedIps:     nil,
		Authentication: &AuthenticationSettings{
			DohAuthOnly: true,
			DohPasswordHash: &AuthenticationSettings_PasswordHashBcrypt{
				PasswordHashBcrypt: []byte("test-hash"),
			},
		},
	}, {
		Id:               "3333cccc",
		Name:             "3333cccc-name",
		FilteringEnabled: false,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("3.3.3.3")),
		DedicatedIps:     nil,
		Authentication: &AuthenticationSettings{
			DohAuthOnly:     false,
			DohPasswordHash: nil,
		},
	}, {
		Id:               "4444dddd",
		Name:             "My Auto-Device",
		HumanIdLower:     "my-auto--device",
		FilteringEnabled: true,
	}}

	customDomainPending := &CustomDomain{
		Domains: []string{
			"pending-1.domain.example",
			"pending-2.domain.example",
		},
		State: &CustomDomain_Pending_{
			Pending: &CustomDomain_Pending{
				WellKnownPath: "/.well-known/abc/def",
				Expire:        timestamppb.New(TestPendingExpire),
			},
		},
	}

	customDomainCurrent := &CustomDomain{
		Domains: []string{
			"current-1.domain.example",
			"current-2.domain.example",
		},
		State: &CustomDomain_Current_{
			Current: &CustomDomain_Current{
				CertName:  "abcdefgh",
				NotBefore: timestamppb.New(TestNotBefore),
				NotAfter:  timestamppb.New(TestNotAfter),
				Enabled:   true,
			},
		},
	}

	customDomain := &CustomDomainSettings{
		Domains: []*CustomDomain{
			customDomainCurrent,
			customDomainPending,
		},
		Enabled: true,
	}

	week := &WeeklyRange{
		Sun: nil,
		Mon: dayRange,
		Tue: dayRange,
		Wed: dayRange,
		Thu: dayRange,
		Fri: dayRange,
		Sat: nil,
	}

	return &DNSProfile{
		DnsId:            TestProfileIDStr,
		FilteringEnabled: true,
		QueryLogEnabled:  true,
		Deleted:          false,
		SafeBrowsing: &SafeBrowsingSettings{
			Enabled:               true,
			BlockDangerousDomains: true,
			BlockNrd:              false,
		},
		Parental: &ParentalSettings{
			Enabled:           false,
			BlockAdult:        false,
			GeneralSafeSearch: false,
			YoutubeSafeSearch: false,
			BlockedServices:   []string{"youtube"},
			Schedule: &ScheduleSettings{
				Tmz:         "GMT",
				WeeklyRange: week,
			},
		},
		RuleLists: &RuleListsSettings{
			Enabled: true,
			Ids:     []string{"1"},
		},
		Devices:             devices,
		CustomRules:         []string{"||example.org^"},
		FilteredResponseTtl: durationpb.New(10 * time.Second),
		BlockPrivateRelay:   true,
		BlockFirefoxCanary:  true,
		IpLogEnabled:        true,
		AutoDevicesEnabled:  true,
		BlockingMode: &DNSProfile_BlockingModeCustomIp{
			BlockingModeCustomIp: &BlockingModeCustomIP{
				Ipv4: ipToBytes(tb, netip.MustParseAddr("1.2.3.4")),
				Ipv6: ipToBytes(tb, netip.MustParseAddr("1234::cdef")),
			},
		},
		Access: &AccessSettings{
			AllowlistCidr: []*CidrRange{{
				Address: netip.MustParseAddr("1.1.1.0").AsSlice(),
				Prefix:  24,
			}},
			BlocklistCidr: []*CidrRange{{
				Address: netip.MustParseAddr("2.2.2.0").AsSlice(),
				Prefix:  24,
			}},
			AllowlistAsn:         []uint32{1},
			BlocklistAsn:         []uint32{2},
			BlocklistDomainRules: []string{"block.test"},
			Enabled:              true,
		},
		RateLimit: &RateLimitSettings{
			Enabled: true,
			Rps:     100,
			ClientCidr: []*CidrRange{{
				Address: netip.MustParseAddr("5.5.5.0").AsSlice(),
				Prefix:  24,
			}},
		},
		BlockChromePrefetch: true,
		CustomDomain:        customDomain,
		AccountId:           TestAccountIDStr,
	}
}

// ipToBytes is a wrapper around netip.Addr.MarshalBinary.
func ipToBytes(tb testing.TB, ip netip.Addr) (b []byte) {
	tb.Helper()

	b, err := ip.MarshalBinary()
	require.NoError(tb, err)

	return b
}

// newProfile returns a new profile for tests.  Keep in sync with
// [NewTestDNSProfile].
func newProfile(tb testing.TB) (p *agd.Profile) {
	tb.Helper()

	wantLoc, err := agdtime.LoadLocation("GMT")
	require.NoError(tb, err)

	dayIvl := &filter.DayInterval{
		Start: 0,
		End:   60,
	}

	wantCustomFilter := &filter.ConfigCustom{
		Filter: custom.New(&custom.Config{
			Logger: slogutil.NewDiscardLogger(),
			Rules:  []filter.RuleText{"||example.org^"},
		}),
		Enabled: true,
	}

	wantParental := &filter.ConfigParental{
		PauseSchedule: &filter.ConfigSchedule{
			Week: &filter.WeeklySchedule{
				nil,
				dayIvl,
				dayIvl,
				dayIvl,
				dayIvl,
				dayIvl,
				nil,
			},
			TimeZone: wantLoc,
		},
		BlockedServices: []filter.BlockedServiceID{
			"youtube",
		},
		Enabled:                  false,
		AdultBlockingEnabled:     false,
		SafeSearchGeneralEnabled: false,
		SafeSearchYouTubeEnabled: false,
	}

	wantRuleList := &filter.ConfigRuleList{
		IDs:     []filter.ID{"1"},
		Enabled: true,
	}

	wantSafeBrowsing := &filter.ConfigSafeBrowsing{
		Enabled:                       true,
		DangerousDomainsEnabled:       true,
		NewlyRegisteredDomainsEnabled: false,
	}

	wantBlockingMode := &dnsmsg.BlockingModeCustomIP{
		IPv4: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		IPv6: []netip.Addr{netip.MustParseAddr("1234::cdef")},
	}

	wantAccess := access.NewDefaultProfile(&access.ProfileConfig{
		AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
		BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
		AllowedASN:           []geoip.ASN{1},
		BlockedASN:           []geoip.ASN{2},
		BlocklistDomainRules: []string{"block.test"},
	})

	wantCustomDomains := &agd.AccountCustomDomains{
		Domains: []*agd.CustomDomainConfig{{
			State: &agd.CustomDomainStateCurrent{
				CertName:  "abcdefgh",
				NotBefore: TestNotBefore,
				NotAfter:  TestNotAfter,
				Enabled:   true,
			},
			Domains: []string{
				"current-1.domain.example",
				"current-2.domain.example",
			},
		}, {
			State: &agd.CustomDomainStatePending{
				WellKnownPath: "/.well-known/abc/def",
				Expire:        TestPendingExpire,
			},
			Domains: []string{
				"pending-1.domain.example",
				"pending-2.domain.example",
			},
		}},
		Enabled: true,
	}

	wantRateLimiter := agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: []netip.Prefix{netip.MustParsePrefix("5.5.5.0/24")},
		RPS:           100,
		Enabled:       true,
	}, 1*datasize.KB)

	return &agd.Profile{
		FilterConfig: &filter.ConfigClient{
			Custom:       wantCustomFilter,
			Parental:     wantParental,
			RuleList:     wantRuleList,
			SafeBrowsing: wantSafeBrowsing,
		},
		Access:       wantAccess,
		BlockingMode: wantBlockingMode,
		Ratelimiter:  wantRateLimiter,
		ID:           TestProfileID,
		DeviceIDs: container.NewMapSet(
			TestDeviceID,
			"2222bbbb",
			"3333cccc",
			"4444dddd",
		),
		FilteredResponseTTL: 10 * time.Second,
		AutoDevicesEnabled:  true,
		BlockChromePrefetch: true,
		BlockFirefoxCanary:  true,
		BlockPrivateRelay:   true,
		Deleted:             false,
		FilteringEnabled:    true,
		IPLogEnabled:        true,
		QueryLogEnabled:     true,
		CustomDomains:       wantCustomDomains,
		AccountID:           TestAccountID,
	}
}

// newDevices returns a slice of test devices.
func newDevices(t *testing.T) (d []*agd.Device) {
	t.Helper()

	return []*agd.Device{{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			DoHAuthOnly:  false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               TestDeviceID,
		LinkedIP:         netip.MustParseAddr("1.1.1.1"),
		Name:             "1111aaaa-name",
		DedicatedIPs:     []netip.Addr{netip.MustParseAddr("1.1.1.2")},
		FilteringEnabled: false,
	}, {
		Auth: &agd.AuthSettings{
			Enabled:      true,
			DoHAuthOnly:  true,
			PasswordHash: agdpasswd.NewPasswordHashBcrypt([]byte("test-hash")),
		},
		ID:               "2222bbbb",
		LinkedIP:         netip.MustParseAddr("2.2.2.2"),
		Name:             "2222bbbb-name",
		DedicatedIPs:     nil,
		FilteringEnabled: true,
	}, {
		Auth: &agd.AuthSettings{
			Enabled:      true,
			DoHAuthOnly:  false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               "3333cccc",
		LinkedIP:         netip.MustParseAddr("3.3.3.3"),
		Name:             "3333cccc-name",
		DedicatedIPs:     nil,
		FilteringEnabled: false,
	}, {
		Auth: &agd.AuthSettings{
			Enabled:      false,
			DoHAuthOnly:  false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               "4444dddd",
		Name:             "My Auto-Device",
		HumanIDLower:     "my-auto--device",
		FilteringEnabled: true,
	}}
}

func BenchmarkDNSProfile_ToInternal(b *testing.B) {
	dp := NewTestDNSProfile(b)
	ctx := context.Background()

	errColl := agdtest.NewErrorCollector()

	var prof *agd.Profile
	var err error

	b.ReportAllocs()
	for b.Loop() {
		prof, _, _, err = dp.toInternal(
			ctx,
			TestLogger,
			errColl,
			TestBind,
			TestLogger,
			EmptyProfileDBMetrics{},
			TestRespSzEst,
			true,
		)
	}

	require.NotNil(b, prof)
	require.NoError(b, err)

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendpb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSProfile_ToInternal-16    	   45411	     26183 ns/op	    3896 B/op	      76 allocs/op
}
