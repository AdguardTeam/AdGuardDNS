package serviceblock_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/serviceblock"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Common blocked service IDs for tests.
const (
	testSvcID1          agd.BlockedServiceID = "svc_1"
	testSvcID2          agd.BlockedServiceID = "svc_2"
	testSvcIDNotPresent agd.BlockedServiceID = "svc_not_present"
)

// testData is a sample of a service index response.
//
// See https://github.com/AdguardTeam/HostlistsRegistry/blob/main/assets/services.json.
const testData string = `{
  "blocked_services": [
    {
      "id": "` + string(testSvcID1) + `",
      "name": "Service 1",
      "rules": [
        "||service-1.example^"
      ]
    },
    {
      "id": "` + string(testSvcID2) + `",
      "name": "Service 2",
      "rules": [
        "||service-2.example^"
      ]
    }
  ]
}`

func TestFilter(t *testing.T) {
	reqCh := make(chan struct{}, 1)
	cachePath, srvURL := filtertest.PrepareRefreshable(t, reqCh, testData, http.StatusOK)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) {
			panic("not implemented")
		},
	}

	refr := internal.NewRefreshable(&internal.RefreshableConfig{
		URL:       srvURL,
		ID:        agd.FilterListIDBlockedService,
		CachePath: cachePath,
		Staleness: filtertest.Staleness,
		Timeout:   filtertest.Timeout,
		MaxSize:   filtertest.FilterMaxSize,
	})

	f := serviceblock.New(refr, errColl)

	ctx := context.Background()
	err := f.Refresh(ctx, 0, false, false)
	require.NoError(t, err)

	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	rls := f.RuleLists(ctx, []agd.BlockedServiceID{
		testSvcID1,
		testSvcID2,
		testSvcIDNotPresent,
	})
	require.Len(t, rls, 2)

	wantSvcIDs := []agd.BlockedServiceID{
		testSvcID1,
		testSvcID2,
	}

	gotFltIDs := make([]agd.FilterListID, 2)
	gotSvcIDs := make([]agd.BlockedServiceID, 2)
	gotFltIDs[0], gotSvcIDs[0] = rls[0].ID()
	gotFltIDs[1], gotSvcIDs[1] = rls[1].ID()
	assert.Equal(t, agd.FilterListIDBlockedService, gotFltIDs[0])
	assert.Equal(t, agd.FilterListIDBlockedService, gotFltIDs[1])
	assert.ElementsMatch(t, wantSvcIDs, gotSvcIDs)
}
