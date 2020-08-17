package ratelimit

import (
	"fmt"
	"net"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/stretchr/testify/assert"
)

func TestRatelimiting(t *testing.T) {
	// rate limit is 1 per sec
	c := caddy.NewTestController("dns", `ratelimit 1`)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)

	if err != nil {
		t.Fatal("Failed to initialize the plugin")
	}

	allowed, _, err := p.allowRequest("127.0.0.1")

	if err != nil || !allowed {
		t.Fatal("First request must have been allowed")
	}

	allowed, _, err = p.allowRequest("127.0.0.1")

	if err != nil || allowed {
		t.Fatal("Second request must have been ratelimited")
	}
}

func TestBackOff(t *testing.T) {
	// rate limit is 1 per sec
	// backoff is 2 for 30 minutes
	c := caddy.NewTestController("dns", `ratelimit 1 2`)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)

	rateLimitersCache.Flush()
	backOffCache.Flush()

	if err != nil {
		t.Fatal("Failed to initialize the plugin")
	}

	ip := "127.0.0.1"
	allowed, _, err := p.allowRequest(ip)

	if err != nil || !allowed {
		t.Fatal("First request must have been allowed")
	}

	allowed, _, err = p.allowRequest(ip)

	if err != nil || allowed {
		t.Fatal("Second request must have been ratelimited")
	}

	// Not enough for backoff to kick in
	assert.False(t, p.isBackOff(ip))

	// Get it ratelimited one more time
	_, _, _ = p.allowRequest(ip)

	// Still not enough
	assert.False(t, p.isBackOff(ip))

	// Ok, do it again
	_, _, _ = p.allowRequest(ip)

	// Now we're talking
	assert.True(t, p.isBackOff(ip))
}

func TestWhitelist(t *testing.T) {
	// rate limit is 1 per sec
	c := caddy.NewTestController("dns", `ratelimit 1 { whitelist 127.0.0.2 127.0.0.1 127.0.0.125 }`)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)

	if err != nil {
		t.Fatal("Failed to initialize the plugin")
	}

	allowed, whitelisted, err := p.allowRequest("127.0.0.1")

	if err != nil || !allowed {
		t.Fatal("First request must have been allowed")
	}

	assert.True(t, whitelisted)

	allowed, whitelisted, err = p.allowRequest("127.0.0.1")

	if err != nil || !allowed {
		t.Fatal("Second request must have been allowed due to whitelist")
	}

	assert.True(t, whitelisted)
}

func TestConsulWhitelist(t *testing.T) {
	l := testStartConsulService()
	defer func() { _ = l.Close() }()

	// rate limit is 1 per sec
	cfg := fmt.Sprintf(`ratelimit 1 { 
		consul http://127.0.0.1:%d/v1/catalog/service/test 123 
	}`, l.Addr().(*net.TCPAddr).Port)
	c := caddy.NewTestController("dns", cfg)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)

	assert.Nil(t, p.reloadConsulWhitelist())

	if err != nil {
		t.Fatalf("Failed to initialize the plugin: %v", err)
	}

	allowed, whitelisted, err := p.allowRequest("123.123.123.122")

	if err != nil || !allowed {
		t.Fatal("First request must have been allowed")
	}
	assert.True(t, whitelisted)

	allowed, whitelisted, err = p.allowRequest("123.123.123.122")

	if err != nil || !allowed {
		t.Fatal("Second request must have been allowed due to whitelist")
	}
	assert.True(t, whitelisted)
}
