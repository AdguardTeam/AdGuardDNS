package upstream

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/caddyserver/caddy"
)

func TestSetup(t *testing.T) {
	for _, testcase := range []struct {
		config  string
		failing bool
	}{
		// Failing
		{`upstream`, true},
		{`upstream 1.1.1.1`, false},
		{`upstream 8.8.8.8 { 
					fallback 1.1.1.1 8.8.8.8
				}`, false},
		{`upstream 1.1.1.1:53`, false},
		{`upstream 8.8.8.8:53 { 
					fallback 1.1.1.1:53 8.8.8.8:53
				}`, false},
	} {
		c := caddy.NewTestController("upstream", testcase.config)
		c.ServerBlockKeys = []string{""}
		u, err := setupPlugin(c)

		if testcase.failing {
			assert.NotNil(t, err)
		} else {
			assert.Nil(t, err)
			assert.NotNil(t, u)
		}
	}
}
