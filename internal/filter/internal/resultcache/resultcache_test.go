package resultcache_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/internal/resultcache"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Common keys for tests.
var (
	testKey  = resultcache.DefaultKey("example.com", dns.TypeA, dns.ClassINET, true)
	otherKey = resultcache.DefaultKey("example.org", dns.TypeAAAA, dns.ClassINET, false)
)

// val is the common value for tests.
const val = 123

func TestCache(t *testing.T) {
	c := resultcache.New[int](100)

	c.Set(testKey, val)

	n := c.ItemCount()
	assert.Equal(t, n, 1)

	res, ok := c.Get(testKey)
	assert.Equal(t, res, val)
	assert.True(t, ok)

	res, ok = c.Get(otherKey)
	assert.Equal(t, res, 0)
	assert.False(t, ok)

	c.Clear()

	n = c.ItemCount()
	assert.Equal(t, n, 0)
}

func TestCache_nil(t *testing.T) {
	require.NotPanics(t, func() {
		var c *resultcache.Cache[int]
		c.Set(testKey, val)

		n := c.ItemCount()
		assert.Equal(t, n, 0)

		res, ok := c.Get(testKey)
		assert.Equal(t, res, 0)
		assert.False(t, ok)

		c.Clear()
	})
}
