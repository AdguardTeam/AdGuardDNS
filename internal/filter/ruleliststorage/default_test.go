package ruleliststorage_test

import (
	"net/http"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/filtertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/rulelist"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/ruleliststorage"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefault(t *testing.T) {
	t.Parallel()

	s := newDefaultWithList(t)

	ctx := testutil.ContextWithTimeout(t, filtertest.Timeout)

	assert.True(t, s.HasListID(ctx, filtertest.RuleListID1))
	assert.False(t, s.HasListID(ctx, filtertest.RuleListID2))

	var rls []*rulelist.Refreshable
	rls = s.AppendForListIDs(ctx, rls, []filter.ID{filtertest.RuleListID2})
	assert.Empty(t, rls)

	rls = s.AppendForListIDs(ctx, rls, []filter.ID{filtertest.RuleListID1})
	require.Len(t, rls, 1)

	id, _ := rls[0].ID()
	assert.Equal(t, filtertest.RuleListID1, id)
}

// newDefault is a helper that returns a new *Default set up with one rule list
// with ID [filtertest.RuleListID1].
func newDefaultWithList(tb testing.TB) (s *ruleliststorage.Default) {
	tb.Helper()

	_, ruleListURL := filtertest.PrepareRefreshable(tb, nil, testFilterData, http.StatusOK)
	rlIdxData := filtertest.NewRuleListIndex(ruleListURL.String())
	_, ruleListIdxURL := filtertest.PrepareRefreshable(tb, nil, string(rlIdxData), http.StatusOK)

	s = newDefault(tb, &ruleliststorage.Config{
		IndexStorage: newRuleListIdxStorage(tb, ruleListIdxURL),
	})

	ctx := testutil.ContextWithTimeout(tb, filtertest.Timeout)

	err := s.RefreshInitial(ctx)
	require.NoError(tb, err)

	return s
}
