package dnsfilter

import (
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	for i, testcase := range []struct {
		config  string
		failing bool
	}{
		{`dnsfilter`, false},
		{`dnsfilter { 
					filter /dev/nonexistent/abcdef
				}`, true},
		{`dnsfilter { 
					filter ../tests/dns.txt
				}`, false},
		{`dnsfilter { 
					safebrowsing ../tests/sb.txt
					filter ../tests/dns.txt 
				}`, false},
		{`dnsfilter { 
					parental ../tests/parental.txt
					filter ../tests/dns.txt
				}`, false},
		{`dnsfilter {
					parental ../tests/parental.txt
					filter ../tests/dns.txt
					geoip ../tests/GeoIP2-Country-Test.mmdb
				}`, false},
	} {
		c := caddy.NewTestController("dns", testcase.config)
		c.ServerBlockKeys = []string{""}
		err := setup(c)
		if err != nil {
			if !testcase.failing {
				t.Fatalf("Test #%d expected no errors, but got: %v", i, err)
			}
			continue
		}
		if testcase.failing {
			t.Fatalf("Test #%d expected to fail but it didn't", i)
		}
	}
}

func TestSetupUpdate(t *testing.T) {
	l := testStartFilterServer()
	defer func() {
		_ = l.Close()
		_ = os.Remove("testsb.txt")
		_ = os.Remove("testdns.txt")
		_ = os.Remove("testparental.txt")
	}()

	port := l.Addr().(*net.TCPAddr).Port
	cfg := fmt.Sprintf(`dnsfilter { 
		safebrowsing testsb.txt example.org http://127.0.0.1:%d/filter.txt 3600
		filter testdns.txt http://127.0.0.1:%d/filter.txt 3600
		parental testparental.txt example.org http://127.0.0.1:%d/filter.txt 3600
	}`, port, port, port)

	c := caddy.NewTestController("dns", cfg)
	c.ServerBlockKeys = []string{""}

	err := setup(c)
	assert.Nil(t, err)

	// Check that filters were downloaded
	assert.FileExists(t, "testsb.txt")
	assert.FileExists(t, "testdns.txt")
	assert.FileExists(t, "testparental.txt")

	// Check that they were added to the updatesMap
	updatesMapGuard.Lock()
	assert.Contains(t, updatesMap, "testsb.txt")
	assert.Contains(t, updatesMap, "testdns.txt")
	assert.Contains(t, updatesMap, "testparental.txt")
	updatesMapGuard.Unlock()

	// Check that enginesMap contain necessary elements
	enginesMapGuard.Lock()
	assert.Contains(t, enginesMap, "testsb.txt")
	assert.Contains(t, enginesMap, "testdns.txt")
	assert.Contains(t, enginesMap, "testparental.txt")
	enginesMapGuard.Unlock()

	// TTL is not expired yet
	wasUpdated := updateCheck()
	assert.False(t, wasUpdated)

	// Trigger filters updates
	updatesMapGuard.Lock()
	for _, u := range updatesMap {
		u.lastTimeUpdated = time.Now().Add(-u.ttl).Add(-1 * time.Second)
	}
	updatesMapGuard.Unlock()

	// Check updates
	wasUpdated = updateCheck()
	assert.True(t, wasUpdated)
}
