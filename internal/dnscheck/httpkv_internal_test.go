package dnscheck

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// FlushConsulCache flushes the internal cache of cc.
//
// TODO(a.garipov):  Remove when cache becomes configurable.
func FlushConsulCache(t *testing.T, cc *Consul) {
	t.Helper()

	cc.cache.Flush()
	require.Zero(t, cc.cache.ItemCount())
}
