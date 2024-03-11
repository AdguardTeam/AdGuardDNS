package backendpb

import (
	"context"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testProfileID is the common profile ID for tests.
const testProfileID agd.ProfileID = "prof1234"

// TestUpdTime is the common update time for tests.
var TestUpdTime = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)

// testBind includes any IPv4 address.
var testBind = netip.MustParsePrefix("0.0.0.0/0")

func TestDNSProfile_ToInternal(t *testing.T) {
	ctx := context.Background()

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic(err)
		},
	}

	t.Run("success", func(t *testing.T) {
		got, gotDevices, err := NewTestDNSProfile(t).toInternal(ctx, TestUpdTime, testBind, errColl)
		require.NoError(t, err)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
	})

	t.Run("success_bad_data", func(t *testing.T) {
		var errCollErr error
		savingErrColl := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errCollErr = err
			},
		}
		got, gotDevices, err := newDNSProfileWithBadData(t).toInternal(
			ctx,
			TestUpdTime,
			testBind,
			savingErrColl,
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(t, "backendpb: invalid device settings:"+
			" dedicated ips: ip at index 0: unexpected slice size", errCollErr)

		assert.Equal(t, newProfile(t), got)
		assert.Equal(t, newDevices(t), gotDevices)
	})

	t.Run("invalid_device_ded_ip", func(t *testing.T) {
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
		)
		require.NoError(t, err)
		testutil.AssertErrorMsg(t, "backendpb: invalid device settings:"+
			" dedicated ip \"1.1.1.2\" is not in bind data", errCollErr)

		assert.NotEqual(t, newProfile(t), got)
		assert.NotEqual(t, newDevices(t), gotDevices)
		assert.Len(t, gotDevices, 1)
	})

	t.Run("empty", func(t *testing.T) {
		var emptyDNSProfile *DNSProfile
		_, _, err := emptyDNSProfile.toInternal(ctx, TestUpdTime, testBind, errColl)
		testutil.AssertErrorMsg(t, "profile is nil", err)
	})

	t.Run("deleted", func(t *testing.T) {
		dp := &DNSProfile{
			DnsId:   string(testProfileID),
			Deleted: true,
		}

		got, gotDevices, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, testProfileID)
		assert.True(t, got.Deleted)
		assert.Empty(t, gotDevices)
	})

	t.Run("inv_parental_sch_tmz", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		dp.Parental.Schedule.Tmz = "invalid"

		_, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		testutil.AssertErrorMsg(t, "parental: schedule: loading timezone: unknown time zone invalid", err)
	})

	t.Run("inv_parental_sch_day_range", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		dp.Parental.Schedule.WeeklyRange.Sun = &DayRange{
			Start: durationpb.New(1000000000000),
			End:   nil,
		}

		_, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		testutil.AssertErrorMsg(t, "parental: schedule: weekday Sunday: bad day range: end 0 less than start 16", err)
	})

	t.Run("inv_blocking_mode_v4", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv4 = []byte("1")

		_, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv4: unexpected slice size", err)
	})

	t.Run("inv_blocking_mode_v6", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		bm := dp.BlockingMode.(*DNSProfile_BlockingModeCustomIp)
		bm.BlockingModeCustomIp.Ipv6 = []byte("1")

		_, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		testutil.AssertErrorMsg(t, "blocking mode: bad custom ipv6: unexpected slice size", err)
	})

	t.Run("nil_blocking_mode", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		dp.BlockingMode = nil

		got, gotDevices, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		require.NoError(t, err)
		require.NotNil(t, got)

		wantProf := newProfile(t)
		wantProf.BlockingMode = &dnsmsg.BlockingModeNullIP{}

		assert.Equal(t, wantProf, got)
		assert.Equal(t, newDevices(t), gotDevices)
	})

	t.Run("nil_access", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		dp.Access = nil

		got, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, testProfileID)
		assert.IsType(t, access.EmptyProfile{}, got.Access)
	})

	t.Run("access_disabled", func(t *testing.T) {
		dp := NewTestDNSProfile(t)
		dp.Access = &AccessSettings{
			Enabled: false,
		}

		got, _, err := dp.toInternal(ctx, TestUpdTime, testBind, errColl)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, got.ID, testProfileID)
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
		Id:               "118ffe93",
		Name:             "118ffe93-name",
		FilteringEnabled: false,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("1.1.1.1")),
		DedicatedIps:     [][]byte{ipToBytes(tb, netip.MustParseAddr("1.1.1.2"))},
	}, {
		Id:               "b9e1a762",
		Name:             "b9e1a762-name",
		FilteringEnabled: true,
		LinkedIp:         ipToBytes(tb, netip.MustParseAddr("2.2.2.2")),
		DedicatedIps:     nil,
	}}

	return &DNSProfile{
		DnsId:            string(testProfileID),
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
	}
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
		IPv4: netip.MustParseAddr("1.2.3.4"),
		IPv6: netip.MustParseAddr("1234::cdef"),
	}

	wantAccess := access.NewDefaultProfile(&access.ProfileConfig{
		AllowedNets:          []netip.Prefix{netip.MustParsePrefix("1.1.1.0/24")},
		BlockedNets:          []netip.Prefix{netip.MustParsePrefix("2.2.2.0/24")},
		AllowedASN:           []geoip.ASN{1},
		BlockedASN:           []geoip.ASN{2},
		BlocklistDomainRules: []string{"block.test"},
	})

	return &agd.Profile{
		Parental:     wantParental,
		BlockingMode: wantBlockingMode,
		ID:           testProfileID,
		UpdateTime:   TestUpdTime,
		DeviceIDs: []agd.DeviceID{
			"118ffe93",
			"b9e1a762",
		},
		RuleListIDs:         []agd.FilterListID{"1"},
		CustomRules:         []agd.FilterRuleText{"||example.org^"},
		FilteredResponseTTL: 10 * time.Second,
		SafeBrowsing:        wantSafeBrowsing,
		Access:              wantAccess,
		RuleListsEnabled:    true,
		FilteringEnabled:    true,
		QueryLogEnabled:     true,
		Deleted:             false,
		BlockPrivateRelay:   true,
		BlockFirefoxCanary:  true,
		IPLogEnabled:        true,
	}
}

// newDevices returns a slice of test devices.
func newDevices(t *testing.T) (d []*agd.Device) {
	t.Helper()

	return []*agd.Device{{
		ID:               "118ffe93",
		LinkedIP:         netip.MustParseAddr("1.1.1.1"),
		Name:             "118ffe93-name",
		DedicatedIPs:     []netip.Addr{netip.MustParseAddr("1.1.1.2")},
		FilteringEnabled: false,
	}, {
		ID:               "b9e1a762",
		LinkedIP:         netip.MustParseAddr("2.2.2.2"),
		Name:             "b9e1a762-name",
		DedicatedIPs:     nil,
		FilteringEnabled: true,
	}}
}

// ipToBytes is a wrapper around netip.Addr.MarshalBinary.
func ipToBytes(tb testing.TB, ip netip.Addr) (b []byte) {
	tb.Helper()

	b, err := ip.MarshalBinary()
	require.NoError(tb, err)

	return b
}

func TestSyncTimeFromTrailer(t *testing.T) {
	milliseconds := strconv.FormatInt(TestUpdTime.UnixMilli(), 10)

	testCases := []struct {
		in        metadata.MD
		wantError string
		want      time.Time
		name      string
	}{{
		in:        metadata.MD{},
		wantError: "empty value",
		want:      time.Time{},
		name:      "no_key",
	}, {
		in:        metadata.MD{"sync_time": []string{}},
		wantError: "empty value",
		want:      time.Time{},
		name:      "empty_key",
	}, {
		in:        metadata.MD{"sync_time": []string{""}},
		wantError: `invalid value: strconv.ParseInt: parsing "": invalid syntax`,
		want:      time.Time{},
		name:      "empty_value",
	}, {
		in:        metadata.MD{"sync_time": []string{milliseconds}},
		wantError: "",
		want:      TestUpdTime,
		name:      "success",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			syncTime, err := syncTimeFromTrailer(tc.in)
			testutil.AssertErrorMsg(t, tc.wantError, err)
			assert.True(t, tc.want.Equal(syncTime), "want %s; got %s", tc.want, syncTime)
		})
	}
}

var (
	errSink  error
	profSink *agd.Profile
)

func BenchmarkDNSProfile_ToInternal(b *testing.B) {
	dp := NewTestDNSProfile(b)
	ctx := context.Background()

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, err error) {
			panic(err)
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		profSink, _, errSink = dp.toInternal(ctx, TestUpdTime, testBind, errColl)
	}

	require.NotNil(b, profSink)
	require.NoError(b, errSink)

	// Most recent result, on a ThinkPad X13:
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendpb
	//	cpu: AMD Ryzen 7 PRO 4750U with Radeon Graphics
	//	BenchmarkDNSProfile_ToInternal
	//	BenchmarkDNSProfile_ToInternal-16         157513             10340 ns/op            1148 B/op       27 allocs/op
}
