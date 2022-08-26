package dnscheck_test

import (
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
)

func TestMain(m *testing.M) {
	agdtest.DiscardLogOutput(m)
}

// Test data.
var (
	testRemoteIP = netip.MustParseAddr("1.2.3.4")
)
