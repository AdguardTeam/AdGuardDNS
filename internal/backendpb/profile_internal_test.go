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
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestDNSProfile_ToInternal(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	errColl := agdtest.NewErrorCollector()

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		got, gotDevices, err := NewTestDNSProfile(t).toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		require.NoError(t, err)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
	})

	t.Run("success_bad_data", func(t *testing.T) {
		t.Parallel()

		var errCollErr error
		savingErrColl := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errCollErr = err
			},
		}
		got, gotDevices, err := newDNSProfileWithBadData(t).toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			savingErrColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(
			t,
			`backendpb: bad device settings for device with id "inv-d-ip":`+
				" dedicated ips: ip at index 0: unexpected slice size",
			errCollErr,
		)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
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
		got, gotDevices, err := NewTestDNSProfile(t).toInternal(
			ctx,
			TestUpdTime,
			bindSet,
			savingErrColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(
			t,
			`backendpb: bad device settings for device with id "`+TestDeviceIDStr+`":`+
				" dedicated ips: at index 0: \"1.1.1.2\" is not in bind data",
			errCollErr,
		)

		assert.NotEqual(t, newProfile(t), got)
		assert.NotEqual(t, newDevices(t), gotDevices)
		assert.Len(t, gotDevices, 3)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		var emptyDNSProfile *DNSProfile
		_, _, err := emptyDNSProfile.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(t, "profile is nil", err)
	})

	t.Run("deleted", func(t *testing.T) {
		t.Parallel()

		dp := &DNSProfile{
			DnsId:   TestProfileIDStr,
			Deleted: true,
		}

		got, gotDevices, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, TestProfileID)
		assert.True(t, got.Deleted)
		assert.Empty(t, gotDevices)
	})

	t.Run("inv_parental_sch_tmz", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Parental.Schedule.Tmz = "invalid"

		_, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(
			t,
			"parental: schedule: loading timezone: unknown time zone invalid",
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

		_, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(
			t,
			"parental: schedule: weekday Sunday: bad day range: end 0 less than start 16",
			err,
		)
	})

	t.Run("inv_blocking_mode_v4", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv4 = []byte("1")

		_, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv4: unexpected slice size", err)
	})

	t.Run("inv_blocking_mode_v6", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv6 = []byte("1")

		_, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv6: unexpected slice size", err)
	})

	t.Run("nil_ips_blocking_mode", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv4 = nil
		bm.BlockingModeCustomIp.Ipv6 = nil

		_, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		testutil.AssertErrorMsg(t, "blocking mode: no valid custom ips found", err)
	})

	t.Run("nil_blocking_mode", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.BlockingMode = nil

		got, gotDevices, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
		require.NoError(t, err)
		require.NotNil(t, got)

		wantProf := newProfile(t)
		wantProf.BlockingMode = &dnsmsg.BlockingModeNullIP{}

		assert.Equal(t, wantProf, got)
		assert.Equal(t, newDevices(t), gotDevices)
	})

	t.Run("nil_access", func(t *testing.T) {
		t.Parallel()

		dp := NewTestDNSProfile(t)
		dp.Access = nil

		got, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
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

		got, _, err := dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
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

// NewTestDNSProfile returns a new instance of *DNSProfile for tests.
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
				Tmz: "GMT",
				WeeklyRange: &WeeklyRange{
					Sun: nil,
					Mon: dayRange,
					Tue: dayRange,
					Wed: dayRange,
					Thu: dayRange,
					Fri: dayRange,
					Sat: nil,
				},
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
	}
}

// ipToBytes is a wrapper around netip.Addr.MarshalBinary.
func ipToBytes(tb testing.TB, ip netip.Addr) (b []byte) {
	tb.Helper()

	b, err := ip.MarshalBinary()
	require.NoError(tb, err)

	return b
}

// newProfile returns a new profile for tests.
func newProfile(tb testing.TB) (p *agd.Profile) {
	tb.Helper()

	wantLoc, err := agdtime.LoadLocation("GMT")
	require.NoError(tb, err)

	dayRange := agd.DayRange{
		Start: 0,
		End:   59,
	}

	wantParental := &agd.ParentalProtectionSettings{
		Schedule: &agd.ParentalProtectionSchedule{
			Week: &agd.WeeklySchedule{
				agd.ZeroLengthDayRange(),
				dayRange,
				dayRange,
				dayRange,
				dayRange,
				dayRange,
				agd.ZeroLengthDayRange(),
			},
			TimeZone: wantLoc,
		},
		BlockedServices:   []agd.BlockedServiceID{"youtube"},
		Enabled:           false,
		BlockAdult:        false,
		GeneralSafeSearch: false,
		YoutubeSafeSearch: false,
	}

	wantSafeBrowsing := &agd.SafeBrowsingSettings{
		Enabled:                     true,
		BlockDangerousDomains:       true,
		BlockNewlyRegisteredDomains: false,
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

	wantRateLimiter := agd.NewDefaultRatelimiter(&agd.RatelimitConfig{
		ClientSubnets: []netip.Prefix{netip.MustParsePrefix("5.5.5.0/24")},
		RPS:           100,
		Enabled:       true,
	}, 1*datasize.KB)

	return &agd.Profile{
		Parental:     wantParental,
		BlockingMode: wantBlockingMode,
		ID:           TestProfileID,
		UpdateTime:   TestUpdTime,
		DeviceIDs: []agd.DeviceID{
			TestDeviceID,
			"2222bbbb",
			"3333cccc",
			"4444dddd",
		},
		RuleListIDs:         []agd.FilterListID{"1"},
		CustomRules:         []agd.FilterRuleText{"||example.org^"},
		FilteredResponseTTL: 10 * time.Second,
		Ratelimiter:         wantRateLimiter,
		SafeBrowsing:        wantSafeBrowsing,
		Access:              wantAccess,
		RuleListsEnabled:    true,
		FilteringEnabled:    true,
		QueryLogEnabled:     true,
		Deleted:             false,
		BlockPrivateRelay:   true,
		BlockFirefoxCanary:  true,
		IPLogEnabled:        true,
		AutoDevicesEnabled:  true,
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

var (
	errSink  error
	profSink *agd.Profile
)

func BenchmarkDNSProfile_ToInternal(b *testing.B) {
	dp := NewTestDNSProfile(b)
	ctx := context.Background()

	errColl := agdtest.NewErrorCollector()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		profSink, _, errSink = dp.toInternal(
			ctx,
			TestUpdTime,
			TestBind,
			errColl,
			EmptyMetrics{},
			TestRespSzEst,
		)
	}

	require.NotNil(b, profSink)
	require.NoError(b, errSink)

	// Most recent result, on a ThinkPad X13:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendpb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSProfile_ToInternal-16    	   67160	     22130 ns/op	    3048 B/op	      51 allocs/op
}
