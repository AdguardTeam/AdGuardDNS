package dnsdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
)

func TestPluginRecordMsg(t *testing.T) {
	path := filepath.Join(os.TempDir(), "db.bin")
	defer func() {
		_ = os.Remove(path)
	}()

	configText := fmt.Sprintf(`dnsdb %s`, path)
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}

	p, err := parse(c)
	if err != nil {
		t.Fatal(err)
	}

	// Emulate a DNS response
	p.Next = backendResponse()
	ctx := context.TODO()

	// Test DNS message
	req := new(dns.Msg)
	req.SetQuestion("badhost.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)

	// Call the plugin
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	// Get the db
	db, ok := dnsDBMap[""]
	assert.True(t, ok)
	assert.NotNil(t, db)

	// Assert that everything was written properly
	assert.Equal(t, 1, len(db.buffer))

	rec, _ := db.buffer["badhost_A"]
	assert.NotNil(t, rec)
	assert.Equal(t, 1, len(rec))
	assert.Equal(t, "badhost", rec[0].DomainName)
}

// Return response with an A record
func backendResponse() plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Response, m.RecursionAvailable = true, true

		m.Answer = []dns.RR{
			test.A("badhost. 0 IN A 37.220.26.135"),
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})
}
