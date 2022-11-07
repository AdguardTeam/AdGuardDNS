package dnscheck_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/golibs/testutil"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// Test data.
var (
	testRemoteIP = netip.MustParseAddr("1.2.3.4")
)
