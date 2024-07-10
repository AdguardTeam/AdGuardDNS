package agdcache_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdcache"
	"github.com/stretchr/testify/assert"
)

func TestManager(t *testing.T) {
	const (
		cacheID            = "cacheID"
		cacheIDNonExisting = "non_existing_cache_id"
	)

	isCleared := false
	mc := &mockClearer{
		onClear: func() {
			isCleared = true
		},
	}

	m := agdcache.NewDefaultManager()
	m.Add(cacheID, mc)
	m.ClearByID(cacheID)

	assert.True(t, isCleared)

	assert.NotPanics(t, func() { m.ClearByID(cacheIDNonExisting) })
}

// mockClearer is the mock implementation of the [agdcache.Clearer] for tests.
type mockClearer struct {
	onClear func()
}

// type check
var _ agdcache.Clearer = (*mockClearer)(nil)

// Clear implements the [agdcache.Clearer] interface for *mockClearer.
func (mc *mockClearer) Clear() {
	mc.onClear()
}
