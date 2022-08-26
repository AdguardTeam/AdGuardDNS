package dnsserver_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
)

func TestMain(m *testing.M) {
	dnsservertest.DiscardLogOutput(m)
}
