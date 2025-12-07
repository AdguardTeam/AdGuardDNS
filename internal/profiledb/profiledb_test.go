package profiledb_test

import (
	"cmp"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/profiledbtest"
	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/require"
)

// Common IPs for tests
var (
	testClientIPv4      = netip.MustParseAddr("192.0.2.1")
	testOtherClientIPv4 = netip.MustParseAddr("192.0.2.2")

	testDedicatedIPv4      = netip.MustParseAddr("192.0.2.3")
	testOtherDedicatedIPv4 = netip.MustParseAddr("192.0.2.4")
)

// newProfileDB is a helper for creating the profile database for tests.  c may
// be nil, and all zero-value fields in c are replaced with defaults for tests.
func newProfileDB(tb testing.TB, c *profiledb.Config) (db *profiledb.Default) {
	tb.Helper()

	c = cmp.Or(c, &profiledb.Config{})

	c.Logger = cmp.Or(c.Logger, profiledbtest.Logger)
	c.BaseCustomLogger = cmp.Or(c.BaseCustomLogger, profiledbtest.Logger)
	c.ProfileAccessConstructor = cmp.Or(
		c.ProfileAccessConstructor,
		profiledbtest.ProfileAccessConstructor,
	)

	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
	c.CustomDomainDB = cmp.Or[profiledb.CustomDomainDB](
		c.CustomDomainDB,
		profiledb.EmptyCustomDomainDB{},
	)
	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Metrics = cmp.Or[profiledb.Metrics](c.Metrics, profiledb.EmptyMetrics{})
	c.Storage = cmp.Or[profiledb.Storage](c.Storage, agdtest.NewProfileStorage())

	c.CacheFilePath = cmp.Or(c.CacheFilePath, "none")
	c.CacheFileIvl = cmp.Or(c.CacheFileIvl, 1*time.Minute)

	c.FullSyncIvl = cmp.Or(c.FullSyncIvl, 1*time.Minute)
	c.FullSyncRetryIvl = cmp.Or(c.FullSyncRetryIvl, 1*time.Minute)

	c.ResponseSizeEstimate = cmp.Or(c.ResponseSizeEstimate, profiledbtest.RespSzEst)

	db, err := profiledb.New(c)
	require.NoError(tb, err)

	return db
}

// newDefaultProfileDB returns a new default profile database for tests.
// devicesCh receives the devices that the storage should return in its
// response.
func newDefaultProfileDB(tb testing.TB, devices <-chan []*agd.Device) (db *profiledb.Default) {
	tb.Helper()

	ps := agdtest.NewProfileStorage()
	ps.OnProfiles = func(
		_ context.Context,
		_ *profiledb.StorageProfilesRequest,
	) (resp *profiledb.StorageProfilesResponse, err error) {
		devices, _ := testutil.RequireReceive(tb, devices, profiledbtest.Timeout)
		devIDs := container.NewMapSet[agd.DeviceID]()
		for _, d := range devices {
			devIDs.Add(d.ID)
		}

		return &profiledb.StorageProfilesResponse{
			Profiles: []*agd.Profile{{
				CustomDomains:            &agd.AccountCustomDomains{},
				AdultBlockingMode:        &dnsmsg.BlockingModeNullIP{},
				BlockingMode:             &dnsmsg.BlockingModeNullIP{},
				SafeBrowsingBlockingMode: &dnsmsg.BlockingModeNullIP{},
				ID:                       profiledbtest.ProfileID,
				DeviceIDs:                devIDs,
			}},
			Devices: devices,
		}, nil
	}

	db = newProfileDB(tb, &profiledb.Config{
		Storage:       ps,
		CacheFilePath: "none",
	})

	ctx := profiledbtest.ContextWithTimeout(tb)
	require.NoError(tb, db.Refresh(ctx))

	return db
}
