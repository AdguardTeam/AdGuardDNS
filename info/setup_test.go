package info

import (
	"testing"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	for i, testcase := range []struct {
		config  string
		failing bool
	}{
		// Failing
		{`info`, true},
		{`info 100`, true},
		{`info { 
					domain adguard.com
				}`, true},
		{`info {
					domain adguard.com
					protocol test
				}`, true},
		// Success
		{`info {
					domain adguard.com
					protocol auto
					type test
					addr 176.103.130.135
				}`, false},
		{`info {
					canary dnscheck.adguard.com
					domain adguard.com
					protocol auto
					type test
					addr 176.103.130.132 176.103.130.134 2a00:5a60::bad1:ff 2a00:5a60::bad2:ff
				}`, false},
	} {
		c := caddy.NewTestController("info", testcase.config)
		c.ServerBlockKeys = []string{""}
		_, err := setupPlugin(c)
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
