package serviceblock_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/refreshable"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/serviceblock"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFilter(t *testing.T) {
	reqCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(
		t,
		reqCh,
		filtertest.BlockedServiceIndex,
		http.StatusOK,
	)

	f, err := serviceblock.New(&serviceblock.Config{
		Refreshable: &refreshable.Config{
			Logger:    slogutil.NewDiscardLogger(),
			URL:       srvURL,
			ID:        filter.IDBlockedService,
			CachePath: cachePath,
			Staleness: filtertest.Staleness,
			Timeout:   filtertest.Timeout,
			MaxSize:   filtertest.FilterMaxSize,
		},
		ErrColl: agdtest.NewErrorCollector(),
		Metrics: filter.EmptyMetrics{},
	})

	require.NoError(t, err)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)
	err = f.Refresh(ctx, agdcache.EmptyManager{}, 0, false, false)
	require.NoError(t, err)

	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	rls := f.RuleLists(ctx, []filter.BlockedServiceID{
		filtertest.BlockedServiceID1,
		filtertest.BlockedServiceID2,
		filtertest.BlockedServiceIDDoesNotExist,
	})
	require.Len(t, rls, 2)

	wantSvcIDs := []filter.BlockedServiceID{
		filtertest.BlockedServiceID1,
		filtertest.BlockedServiceID2,
	}

	gotFltIDs := make([]filter.ID, 2)
	gotSvcIDs := make([]filter.BlockedServiceID, 2)
	gotFltIDs[0], gotSvcIDs[0] = rls[0].ID()
	gotFltIDs[1], gotSvcIDs[1] = rls[1].ID()
	assert.Equal(t, filter.IDBlockedService, gotFltIDs[0])
	assert.Equal(t, filter.IDBlockedService, gotFltIDs[1])
	assert.ElementsMatch(t, wantSvcIDs, gotSvcIDs)
}
