package serviceblock_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/serviceblock"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common blocked service IDs for tests.
const (
	testSvcID1 agd.BlockedServiceID = "svc_1"
	testSvcID2 agd.BlockedServiceID = "svc_2"
)

// testData is a sample of a service index response.
//
// See https://github.com/atropnikov/HostlistsRegistry/blob/main/assets/services.json.
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
	_, srvURL := filtertest.PrepareRefreshable(t, reqCh, testData, http.StatusOK)

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(ctx context.Context, err error) {
			panic("not implemented")
		},
	}

	f := serviceblock.New(srvURL, errColl)

	ctx := context.Background()
	err := f.Refresh(ctx, 0, false)
	require.NoError(t, err)

	testutil.RequireReceive(t, reqCh, filtertest.Timeout)

	svcIDs := []agd.BlockedServiceID{testSvcID1, testSvcID2}
	rls := f.RuleLists(ctx, svcIDs)
	require.Len(t, rls, 2)

	gotFltIDs := make([]agd.FilterListID, 2)
	gotSvcIDs := make([]agd.BlockedServiceID, 2)
	gotFltIDs[0], gotSvcIDs[0] = rls[0].ID()
	gotFltIDs[1], gotSvcIDs[1] = rls[1].ID()
	assert.Equal(t, agd.FilterListIDBlockedService, gotFltIDs[0])
	assert.Equal(t, agd.FilterListIDBlockedService, gotFltIDs[1])
	assert.ElementsMatch(t, svcIDs, gotSvcIDs)
}
