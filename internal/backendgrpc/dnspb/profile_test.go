package dnspb_test

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
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb"
	"github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/internal/backendtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/custom"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/c2h5oh/datasize"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
)

// Common bind values for tests.
var (
	testBindAll   = backendtest.Bind
	testBindOther = netip.MustParsePrefix("192.0.2.1/32")
)

func TestDNSProfile_ToInternal(t *testing.T) {
	t.Parallel()

	wantDevChg := &profiledb.StorageDeviceChange{}

	profile := backendtest.NewDNSProfile(t)

	t.Run("success", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		got, err := profileToInternal(ctx, profile, testBindAll, backendtest.ErrColl)
		require.NoError(t, err)

		agdtest.AssertEqualProfile(t, newProfile(t), got.Profile)
		assert.Equal(t, newDevices(), got.Devices)
		assert.Equal(t, wantDevChg, got.DeviceChange)
	})

	t.Run("success_bad_data", func(t *testing.T) {
		t.Parallel()

		var errFromErrColl error
		errCollSave := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errFromErrColl = err
			},
		}

		p := newDNSProfileWithBadData(t)

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		got, err := profileToInternal(ctx, p, testBindAll, errCollSave)
		require.NoError(t, err)

		testutil.AssertErrorMsg(
			t,
			`converting device: bad settings for device with id "inv-d-ip":`+
				` dedicated ips: ip at index 0: unexpected slice size`,
			errFromErrColl,
		)

		agdtest.AssertEqualProfile(t, newProfile(t), got.Profile)
		assert.Equal(t, newDevices(), got.Devices)
		assert.Equal(t, wantDevChg, got.DeviceChange)
	})

	t.Run("invalid_device_ded_ip", func(t *testing.T) {
		t.Parallel()
		var errFromErrColl error
		errCollSave := &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) {
				errFromErrColl = err
			},
		}

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		got, err := profileToInternal(
			ctx,
			profile,
			testBindOther,
			errCollSave,
		)
		require.NoError(t, err)

		testutil.AssertErrorMsg(
			t,
			`converting device: bad settings for device with id "`+backendtest.DeviceIDStr+`":`+
				" dedicated ips: at index 0: \"1.1.1.2\" is not in bind data",
			errFromErrColl,
		)

		wantProf := newProfile(t)
		wantProf.DeviceIDs.Delete(backendtest.DeviceID)

		agdtest.AssertEqualProfile(t, wantProf, got.Profile)
		assert.NotEqual(t, newDevices(), got.Devices)
		assert.Len(t, got.Devices, 3)
		assert.Equal(t, wantDevChg, got.DeviceChange)
	})

	t.Run("empty", func(t *testing.T) {
		t.Parallel()

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		_, err := profileToInternal(ctx, nil, testBindAll, backendtest.ErrColl)

		assert.Equal(t, err, errors.ErrNoValue)
	})

	t.Run("deleted_profile", func(t *testing.T) {
		t.Parallel()

		p := &dnspb.DNSProfile{
			AccountIdInt: 1,
			DnsId:        backendtest.ProfileIDStr,
			Deleted:      true,
		}

		ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
		got, err := profileToInternal(ctx, p, testBindAll, backendtest.ErrColl)
		require.NoError(t, err)
		require.NotNil(t, got)

		assert.Equal(t, backendtest.ProfileID, got.Profile.ID)
		assert.True(t, got.Profile.Deleted)
		assert.Empty(t, got.Devices)
		assert.Equal(t, wantDevChg, got.DeviceChange)
	})
}

// newDNSProfileWithBadData is a wrapper around [backendgrpctest.NewDNSProfile]
// which creates new instance of *DNSProfile with device changes included.
func newDNSProfileWithDevChgs(tb testing.TB) (p *dnspb.DNSProfile) {
	tb.Helper()

	p = backendtest.NewDNSProfile(tb)
	p.Devices = nil

	deletedIds := &dnspb.DeviceSettingsChange_Deleted{
		DeviceId: backendtest.DeviceIDStr,
	}
	deletedDeviceChg := &dnspb.DeviceSettingsChange_Deleted_{
		Deleted: deletedIds,
	}
	p.DeviceChanges = []*dnspb.DeviceSettingsChange{{
		Change: deletedDeviceChg,
	}}

	return p
}

// newDNSProfileWithBadData returns a new instance of *DNSProfile with bad
// devices data for tests.
func newDNSProfileWithBadData(tb testing.TB) (p *dnspb.DNSProfile) {
	tb.Helper()

	invalidDevices := []*dnspb.DeviceSettings{{
		Id:               "invalid-too-long-device-id",
		Name:             "device_name",
		FilteringEnabled: true,
		LinkedIp:         backendtest.IPStringToBytes(tb, "1.1.1.1"),
		DedicatedIps:     nil,
	}, {
		Id: "dev-name",
		Name: "invalid-too-long-device-name-invalid-too-long-device-name-" +
			"invalid-too-long-device-name-invalid-too-long-device-name-" +
			"invalid-too-long-device-name-invalid-too-long-device-name",
		FilteringEnabled: true,
		LinkedIp:         backendtest.IPStringToBytes(tb, "1.1.1.1"),
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
		LinkedIp:         backendtest.IPStringToBytes(tb, "1.1.1.1"),
		DedicatedIps:     [][]byte{[]byte("1")},
	}}

	p = backendtest.NewDNSProfile(tb)
	p.Devices = append(p.Devices, invalidDevices...)

	return p
}

// profileToInternal is a wrapper around [dnspb.DNSProfile.ToInternal] that uses
// some test values.
func profileToInternal(
	ctx context.Context,
	pbp *dnspb.DNSProfile,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (res *dnspb.ProfileResult, err error) {
	return pbp.ToInternal(
		ctx,
		backendtest.Logger,
		backendtest.Logger,
		backendtest.ProfileAccessConstructor,
		bindSet,
		errColl,
		backendtest.ResponseSizeEstimate,
		true,
	)
}

// newProfile returns a new profile for tests.  Keep in sync with
// [backendtest.NewDNSProfile].
func newProfile(tb testing.TB) (p *agd.Profile) {
	tb.Helper()

	wantLoc, err := agdtime.LoadLocation("GMT")
	require.NoError(tb, err)

	dayIvl := &filter.DayInterval{
		Start: 0,
		End:   60,
	}

	wantCustomFilter := &filter.ConfigCustomFilter{
		Filter: custom.New(&custom.Config{
			Logger: slogutil.NewDiscardLogger(),
			Rules:  []filter.RuleText{"||example.org^"},
		}),
		Enabled: true,
	}

	wantCategories := &filter.ConfigCategories{
		Enabled: true,
		IDs:     []filter.CategoryID{"games"},
	}

	wantParental := &filter.ConfigParental{
		Categories: wantCategories,
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
	}

	wantCustomRuleList := &filter.ConfigCustomRuleList{
		IDs:     []filter.ID{"1"},
		Enabled: true,
	}

	wantRuleList := &filter.ConfigRuleList{
		IDs:     []filter.ID{"2"},
		Enabled: true,
	}

	wantSafeBrowsing := &filter.ConfigSafeBrowsing{
		Typosquatting: &filter.ConfigTyposquatting{
			Enabled: true,
		},
		Enabled:                 true,
		DangerousDomainsEnabled: true,
	}

	wantAdultBlockingMode := &dnsmsg.BlockingModeCustomIP{
		IPv4: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
		IPv6: []netip.Addr{netip.MustParseAddr("1111::cdef")},
	}

	wantBlockingMode := &dnsmsg.BlockingModeCustomIP{
		IPv4: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		IPv6: []netip.Addr{netip.MustParseAddr("1234::cdef")},
	}

	wantSafeBrowsingBlockingMode := &dnsmsg.BlockingModeCustomIP{
		IPv4: []netip.Addr{netip.MustParseAddr("2.2.2.2")},
		IPv6: []netip.Addr{netip.MustParseAddr("2222::cdef")},
	}

	wantAccess := backendtest.ProfileAccessConstructor.New(&access.ProfileConfig{
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
		FilterConfig: &filter.ConfigClient{
			CustomFilter:   wantCustomFilter,
			CustomRuleList: wantCustomRuleList,
			Parental:       wantParental,
			RuleList:       wantRuleList,
			SafeBrowsing:   wantSafeBrowsing,
		},
		Access:                   wantAccess,
		AdultBlockingMode:        wantAdultBlockingMode,
		BlockingMode:             wantBlockingMode,
		SafeBrowsingBlockingMode: wantSafeBrowsingBlockingMode,
		Ratelimiter:              wantRateLimiter,
		ID:                       backendtest.ProfileID,
		DeviceIDs: container.NewMapSet(
			backendtest.DeviceID,
			"2222bbbb",
			"3333cccc",
			"4444dddd",
		),
		FilteredResponseTTL: 10 * time.Second,
		AutoDevicesEnabled:  true,
		BlockChromePrefetch: true,
		BlockFirefoxCanary:  true,
		BlockPrivateRelay:   true,
		FilteringEnabled:    true,
		IPLogEnabled:        true,
		QueryLogEnabled:     true,
		CustomDomains:       newCustomDomain(),
		AccountID:           backendtest.AccountID,
	}
}

// newDevices returns a slice of test devices.
func newDevices() (d []*agd.Device) {
	return []*agd.Device{{
		Auth: &agd.AuthSettings{
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:           backendtest.DeviceID,
		LinkedIP:     netip.MustParseAddr("1.1.1.1"),
		Name:         "1111aaaa-name",
		DedicatedIPs: []netip.Addr{netip.MustParseAddr("1.1.1.2")},
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
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:           "3333cccc",
		LinkedIP:     netip.MustParseAddr("3.3.3.3"),
		Name:         "3333cccc-name",
		DedicatedIPs: nil,
	}, {
		Auth: &agd.AuthSettings{
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               "4444dddd",
		Name:             "My Auto-Device",
		HumanIDLower:     "my-auto--device",
		FilteringEnabled: true,
	}}
}

// newCustomDomain returns custom-domain settings for tests.
func newCustomDomain() (s *agd.AccountCustomDomains) {
	return &agd.AccountCustomDomains{
		Domains: []*agd.CustomDomainConfig{{
			State: &agd.CustomDomainStateCurrent{
				CertName:  "abcdefgh",
				NotBefore: backendtest.TimeNotBefore,
				NotAfter:  backendtest.TimeNotAfter,
				Enabled:   true,
			},
			Domains: []string{
				"current-1.domain.example",
				"current-2.domain.example",
			},
		}, {
			State: &agd.CustomDomainStatePending{
				WellKnownPath: "/.well-known/abc/def",
				Expire:        backendtest.TimePendingExpire,
			},
			Domains: []string{
				"pending-1.domain.example",
				"pending-2.domain.example",
			},
		}},
		Enabled: true,
	}
}

func TestDNSProfile_ToInternal_access(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		access *dnspb.AccessSettings
		name   string
	}{{
		access: nil,
		name:   "nil_access",
	}, {
		access: &dnspb.AccessSettings{},
		name:   "access_disabled",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := backendtest.NewDNSProfile(t)
			p.Access = tc.access

			ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
			got, err := profileToInternal(ctx, p, testBindAll, backendtest.ErrColl)
			require.NoError(t, err)
			require.NotNil(t, got.Profile)

			assert.Equal(t, got.Profile.ID, backendtest.ProfileID)
			assert.IsType(t, access.EmptyProfile{}, got.Profile.Access)
		})
	}
}

func TestDNSProfile_ToInternal_blockingModeNil(t *testing.T) {
	t.Parallel()

	profDefBlockMode := newProfile(t)
	profDefBlockMode.BlockingMode = &dnsmsg.BlockingModeNullIP{}

	profNilAdult := newProfile(t)
	profNilAdult.AdultBlockingMode = nil

	profNilSafeBrowsing := newProfile(t)
	profNilSafeBrowsing.SafeBrowsingBlockingMode = nil

	testCases := []struct {
		want       *agd.Profile
		setIn      func(p *dnspb.DNSProfile)
		name       string
		wantErrMsg string
	}{{
		want:       profNilAdult,
		setIn:      func(p *dnspb.DNSProfile) { p.AdultBlockingMode = nil },
		name:       "adult_nil",
		wantErrMsg: "",
	}, {
		want:       profDefBlockMode,
		setIn:      func(p *dnspb.DNSProfile) { p.BlockingMode = nil },
		name:       "default_nil",
		wantErrMsg: "",
	}, {
		want:       profNilSafeBrowsing,
		setIn:      func(p *dnspb.DNSProfile) { p.SafeBrowsingBlockingMode = nil },
		name:       "safe_browsing_nil",
		wantErrMsg: "",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := backendtest.NewDNSProfile(t)
			tc.setIn(in)

			ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
			got, err := profileToInternal(ctx, in, testBindAll, backendtest.ErrColl)

			require.NoError(t, err)

			agdtest.AssertEqualProfile(t, tc.want, got.Profile)
			assert.Equal(t, newDevices(), got.Devices)

			wantDevChg := &profiledb.StorageDeviceChange{}
			assert.Equal(t, wantDevChg, got.DeviceChange)
		})
	}
}

func TestDNSProfile_ToInternal_blockingModeErrors(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		setIn      func(p *dnspb.DNSProfile)
		name       string
		wantErrMsg string
	}{{
		setIn: func(p *dnspb.DNSProfile) {
			m := p.AdultBlockingMode.(*dnspb.DNSProfile_AdultBlockingModeCustomIp)
			m.AdultBlockingModeCustomIp.Ipv4 = []byte{'1'}
		},
		name:       "adult_bad_ipv4",
		wantErrMsg: "adult blocking mode: bad custom ipv4: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.AdultBlockingMode.(*dnspb.DNSProfile_AdultBlockingModeCustomIp)
			m.AdultBlockingModeCustomIp.Ipv6 = []byte{'1'}
		},
		name:       "adult_bad_ipv6",
		wantErrMsg: "adult blocking mode: bad custom ipv6: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.AdultBlockingMode.(*dnspb.DNSProfile_AdultBlockingModeCustomIp)
			m.AdultBlockingModeCustomIp.Ipv4 = nil
			m.AdultBlockingModeCustomIp.Ipv6 = nil
		},
		name:       "adult_nils",
		wantErrMsg: "adult blocking mode: no valid custom ips found",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.BlockingMode.(*dnspb.DNSProfile_BlockingModeCustomIp)
			m.BlockingModeCustomIp.Ipv4 = []byte{'1'}
		},
		name:       "bad_ipv4",
		wantErrMsg: "blocking mode: bad custom ipv4: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.BlockingMode.(*dnspb.DNSProfile_BlockingModeCustomIp)
			m.BlockingModeCustomIp.Ipv6 = []byte{'1'}
		},
		name:       "bad_ipv6",
		wantErrMsg: "blocking mode: bad custom ipv6: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.BlockingMode.(*dnspb.DNSProfile_BlockingModeCustomIp)
			m.BlockingModeCustomIp.Ipv4 = nil
			m.BlockingModeCustomIp.Ipv6 = nil
		},
		name:       "nils",
		wantErrMsg: "blocking mode: no valid custom ips found",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.SafeBrowsingBlockingMode.(*dnspb.DNSProfile_SafeBrowsingBlockingModeCustomIp)
			m.SafeBrowsingBlockingModeCustomIp.Ipv4 = []byte{'1'}
		},
		name:       "safe_browsing_bad_ipv4",
		wantErrMsg: "safe browsing blocking mode: bad custom ipv4: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.SafeBrowsingBlockingMode.(*dnspb.DNSProfile_SafeBrowsingBlockingModeCustomIp)
			m.SafeBrowsingBlockingModeCustomIp.Ipv6 = []byte{'1'}
		},
		name:       "safe_browsing_bad_ipv6",
		wantErrMsg: "safe browsing blocking mode: bad custom ipv6: unexpected slice size",
	}, {
		setIn: func(p *dnspb.DNSProfile) {
			m := p.SafeBrowsingBlockingMode.(*dnspb.DNSProfile_SafeBrowsingBlockingModeCustomIp)
			m.SafeBrowsingBlockingModeCustomIp.Ipv4 = nil
			m.SafeBrowsingBlockingModeCustomIp.Ipv6 = nil
		},
		name:       "safe_browsing_nils",
		wantErrMsg: "safe browsing blocking mode: no valid custom ips found",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := backendtest.NewDNSProfile(t)
			tc.setIn(in)

			ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
			got, err := profileToInternal(ctx, in, testBindAll, backendtest.ErrColl)

			require.Nil(t, got.Profile)
			require.Nil(t, got.Devices)
			require.Nil(t, got.DeviceChange)

			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDNSProfile_ToInternal_parentalErrors(t *testing.T) {
	t.Parallel()

	profBadDayRange := backendtest.NewDNSProfile(t)
	profBadDayRange.Parental.Schedule.WeeklyRange.Sun = &dnspb.DayRange{
		Start: durationpb.New(1000000000000),
		End:   nil,
	}

	profBadTimeZone := backendtest.NewDNSProfile(t)
	profBadTimeZone.Parental.Schedule.Tmz = "invalid"

	testCases := []struct {
		in         *dnspb.DNSProfile
		name       string
		wantErrMsg string
	}{{
		in:   profBadDayRange,
		name: "bad_day_range",
		wantErrMsg: "filter config: parental: pause schedule: weekday Sunday: end: out of range: " +
			"1 is less than start 16",
	}, {
		in:   profBadTimeZone,
		name: "bad_time_zone",
		wantErrMsg: "filter config: parental: pause schedule: loading timezone: " +
			"unknown time zone invalid",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
			_, err := profileToInternal(ctx, tc.in, testBindAll, backendtest.ErrColl)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDNSProfile_ToInternal_deviceChanges(t *testing.T) {
	t.Parallel()

	p := newDNSProfileWithDevChgs(t)

	deletedDeviceIds := []agd.DeviceID{
		backendtest.DeviceID,
	}
	wantDevChanges := &profiledb.StorageDeviceChange{
		DeletedDeviceIDs: deletedDeviceIds,
		IsPartial:        true,
	}

	ctx := testutil.ContextWithTimeout(t, backendtest.Timeout)
	got, err := profileToInternal(ctx, p, testBindAll, backendtest.ErrColl)
	require.NoError(t, err)
	require.NotNil(t, got)

	assert.Equal(t, backendtest.ProfileID, got.Profile.ID)
	assert.Empty(t, got.Devices)
	assert.Equal(t, wantDevChanges, got.DeviceChange)
}

func BenchmarkDNSProfile_ToInternal(b *testing.B) {
	ctx := context.Background()

	p := backendtest.NewDNSProfile(b)

	var got *dnspb.ProfileResult
	var err error

	b.ReportAllocs()
	for b.Loop() {
		got, err = p.ToInternal(
			ctx,
			backendtest.Logger,
			backendtest.Logger,
			backendtest.ProfileAccessConstructor,
			testBindAll,
			backendtest.ErrColl,
			backendtest.ResponseSizeEstimate,
			true,
		)
	}

	require.NotNil(b, got)
	require.NoError(b, err)

	// Most recent results:
	//
	//	goos: linux
	//	goarch: amd64
	//	pkg: github.com/AdguardTeam/AdGuardDNS/internal/backendgrpc/dnspb
	//	cpu: AMD Ryzen AI 9 HX PRO 370 w/ Radeon 890M
	//	BenchmarkDNSProfile_ToInternal-24    	  177238	      5971 ns/op	    4632 B/op	      96 allocs/op
}
