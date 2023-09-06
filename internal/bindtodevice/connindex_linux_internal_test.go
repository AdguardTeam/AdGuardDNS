//go:build linux

package bindtodevice

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestSubnetCompare(t *testing.T) {
	want := []netip.Prefix{
		netip.MustParsePrefix("1.0.0.0/24"),
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("1.0.0.0/16"),
		netip.MustParsePrefix("1.2.0.0/16"),
	}
	got := []netip.Prefix{
		netip.MustParsePrefix("1.0.0.0/16"),
		netip.MustParsePrefix("1.0.0.0/24"),
		netip.MustParsePrefix("1.2.0.0/16"),
		netip.MustParsePrefix("1.2.3.0/24"),
	}

	slices.SortFunc(got, subnetCompare)
	assert.Equalf(t, want, got, "got (as strings): %q", got)
}
