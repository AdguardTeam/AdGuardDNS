package prometheus_test

import (
	"net"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	testutil.DiscardLogOutput(m)
}

// testReqDomain is the common request domain for tests.
const testReqDomain = "request-domain.example"

// testServerInfo is the common server information structure for tests.
var testServerInfo = dnsserver.ServerInfo{
	Name:  "test_server",
	Addr:  "127.0.0.1:80",
	Proto: dnsserver.ProtoDNS,
}

// testUDPAddr is the common UDP address for tests.
var testUDPAddr = &net.UDPAddr{
	IP:   net.IP{1, 2, 3, 4},
	Port: 53,
}

// requireMetrics accepts a list of metrics names and checks that
// they exist in the prom registry.
func requireMetrics(t testing.TB, args ...string) {
	t.Helper()

	mf, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	require.NotNil(t, mf)

	// Check that metrics were incremented. If they're present in the collection
	// return by Gatherer, it means that they were used.
	metricsToCheck := map[string]bool{}
	for _, m := range args {
		metricsToCheck[m] = true
	}

	// Delete from metricsToCheck if the metric was found.
	// metricsToCheck must be empty in the end.
	for _, m := range mf {
		delete(metricsToCheck, m.GetName())
	}

	require.Len(t, metricsToCheck, 0, "Some metrics weren't reported: %v", metricsToCheck)
}
