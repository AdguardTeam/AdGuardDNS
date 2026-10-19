package tlsconfig

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPrefixSet(t *testing.T) {
	t.Parallel()

	prefix := netip.MustParsePrefix("192.0.2.0/24")

	set := &prefixSet{}
	assert.Empty(t, set.values())

	set.add(prefix)
	assert.Equal(t, []netip.Prefix{prefix}, set.values())

	set.delete(prefix)
	assert.Empty(t, set.values())
}
