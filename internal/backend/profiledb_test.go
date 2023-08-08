package backend_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/backend"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common test constants.
var (
	syncTime = time.Unix(0, 1_624_443_079_309_000_000)
	updTime  = time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
)

func TestProfileStorage_Profiles(t *testing.T) {
	reqURLStr := ""
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pt := testutil.PanicT{}

		// NOTE: Keep testdata/profiles.json formatted using jq.  Example of a
		// formatting command using sponge(1) from the current directory:
		//
		//	jq '.' ./testdata/profiles.json | sponge ./testdata/profiles.json
		reqURLStr = r.URL.String()
		b, err := os.ReadFile(filepath.Join("testdata", "profiles.json"))
		require.NoError(pt, err)

		_, err = w.Write(b)
		require.NoError(pt, err)
	})

	// TODO(a.garipov): Don't listen on actual sockets and use piped conns
	// instead.  Perhaps, add these to a new network test utility package in the
	// golibs module.
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	require.NoError(t, err)

	c := &backend.ProfileStorageConfig{
		BaseEndpoint: u,
		Now:          func() (t time.Time) { return updTime },
	}

	ds := backend.NewProfileStorage(c)
	require.NotNil(t, ds)

	ctx := context.Background()
	req := &profiledb.StorageRequest{
		SyncTime: syncTime,
	}

	resp, err := ds.Profiles(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Compare against a relative URL since the URL inside an HTTP handler
	// seems to always be relative.
	wantURLStr := fmt.Sprintf("%s?sync_time=%d", backend.PathDNSAPIV1Settings, syncTime.UnixMilli())
	assert.Equal(t, wantURLStr, reqURLStr)

	want := testProfileResp(t)
	assert.Equal(t, want, resp)
}

// testProfileResp returns profile resp corresponding with testdata.
//
// Keep in sync with the testdata one.
func testProfileResp(t *testing.T) (resp *profiledb.StorageResponse) {
	t.Helper()

	wantLoc, err := agdtime.LoadLocation("GMT")
	require.NoError(t, err)

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

	wantLinkedIP := netip.AddrFrom4([4]byte{1, 2, 3, 4})

	wantBlockingMode := dnsmsg.BlockingModeCodec{
		Mode: &dnsmsg.BlockingModeCustomIP{
			IPv4: netip.MustParseAddr("1.2.3.4"),
			IPv6: netip.MustParseAddr("1234::cdef"),
		},
	}

	want := &profiledb.StorageResponse{
		SyncTime: syncTime,
		Profiles: []*agd.Profile{{
			Parental: nil,
			BlockingMode: dnsmsg.BlockingModeCodec{
				Mode: &dnsmsg.BlockingModeNullIP{},
			},
			ID:         "37f97ee9",
			UpdateTime: updTime,
			DeviceIDs: []agd.DeviceID{
				"118ffe93",
				"b9e1a762",
			},
			RuleListIDs:         []agd.FilterListID{"1"},
			CustomRules:         nil,
			FilteredResponseTTL: 10 * time.Second,
			SafeBrowsing:        wantSafeBrowsing,
			RuleListsEnabled:    true,
			FilteringEnabled:    true,
			QueryLogEnabled:     true,
			Deleted:             false,
			BlockPrivateRelay:   true,
			BlockFirefoxCanary:  true,
		}, {
			Parental:     wantParental,
			BlockingMode: wantBlockingMode,
			ID:           "83f3ea8f",
			UpdateTime:   updTime,
			DeviceIDs: []agd.DeviceID{
				"0d7724fa",
				"6d2ac775",
				"94d4c481",
				"ada436e3",
			},
			RuleListIDs:         []agd.FilterListID{"1"},
			CustomRules:         []agd.FilterRuleText{"||example.org^"},
			FilteredResponseTTL: 3600 * time.Second,
			SafeBrowsing:        wantSafeBrowsing,
			RuleListsEnabled:    true,
			FilteringEnabled:    true,
			QueryLogEnabled:     true,
			Deleted:             true,
			BlockPrivateRelay:   false,
			BlockFirefoxCanary:  false,
		}},
		Devices: []*agd.Device{{
			ID:               "118ffe93",
			Name:             "Device 1",
			FilteringEnabled: true,
		}, {
			ID:               "b9e1a762",
			Name:             "Device 2",
			FilteringEnabled: true,
		}, {
			ID:               "0d7724fa",
			Name:             "Device 1",
			FilteringEnabled: true,
		}, {
			ID:               "6d2ac775",
			Name:             "Device 2",
			FilteringEnabled: true,
		}, {
			ID:   "94d4c481",
			Name: "Device 3",
			DedicatedIPs: []netip.Addr{
				netip.MustParseAddr("1.2.3.4"),
			},
			FilteringEnabled: true,
		}, {
			ID:               "ada436e3",
			LinkedIP:         wantLinkedIP,
			Name:             "Device 4",
			FilteringEnabled: true,
		}},
	}

	return want
}
