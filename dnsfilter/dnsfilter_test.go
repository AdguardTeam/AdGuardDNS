package dnsfilter

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestEtcHostsFilter(t *testing.T) {
	text := []byte("127.0.0.1 doubleclick.net\n" + "127.0.0.1 example.org example.net www.example.org www.example.net")
	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tmpfile.Write(text); err != nil {
		t.Fatal(err)
	}
	if err = tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name())

	configText := fmt.Sprintf("dnsfilter {\nfilter %s\n}", tmpfile.Name())
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	for _, testcase := range []struct {
		host     string
		filtered bool
	}{
		{"www.doubleclick.net", false},
		{"doubleclick.net", true},
		{"www2.example.org", false},
		{"www2.example.net", false},
		{"test.www.example.org", false},
		{"test.www.example.net", false},
		{"example.org", true},
		{"example.net", true},
		{"www.example.org", true},
		{"www.example.net", true},
	} {
		req := new(dns.Msg)
		req.SetQuestion(testcase.host+".", dns.TypeA)

		resp := test.ResponseWriter{}
		rrw := dnstest.NewRecorder(&resp)
		rcode, err := p.ServeDNS(ctx, rrw, req)
		if err != nil {
			t.Fatalf("ServeDNS returned error: %s", err)
		}
		if rcode != rrw.Rcode {
			t.Fatalf("ServeDNS return value for host %s has rcode %d that does not match captured rcode %d", testcase.host, rcode, rrw.Rcode)
		}
		A, ok := rrw.Msg.Answer[0].(*dns.A)
		if !ok {
			t.Fatalf("Host %s expected to have result A", testcase.host)
		}
		ip := net.IPv4(0, 0, 0, 0)
		filtered := ip.Equal(A.A)
		if testcase.filtered && testcase.filtered != filtered {
			t.Fatalf("Host %s expected to be filtered, instead it is not filtered", testcase.host)
		}
		if !testcase.filtered && testcase.filtered != filtered {
			t.Fatalf("Host %s expected to be not filtered, instead it is filtered", testcase.host)
		}
	}
}

func TestSafeSearchFilter(t *testing.T) {
	configText := `dnsfilter {
		safesearch
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assertResponseIP(t, rrw.Msg, "forcesafesearch.google.com")
}

// 4-character hash
func TestSafeBrowsingEngine(t *testing.T) {
	configText := `dnsfilter {
		safebrowsing ../tests/sb.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	hash0 := sha256.Sum256([]byte("asdf.testsb.example.org"))
	q0 := hex.EncodeToString(hash0[0:2])
	hash1 := sha256.Sum256([]byte("testsb.example.org"))
	q1 := hex.EncodeToString(hash1[0:2])
	hash2 := sha256.Sum256([]byte("example.org"))
	q2 := hex.EncodeToString(hash2[0:2])
	result, _ := p.getSafeBrowsingEngine().data.MatchHashes(q0 + "." + q1 + "." + q2)
	assert.True(t, len(result) == 1)
	shash := hex.EncodeToString(hash1[:])
	assert.True(t, result[0] == shash)

	assert.True(t, p.getSafeBrowsingEngine().data.MatchHost("testsb.example.org"))
	assert.True(t, !p.getSafeBrowsingEngine().data.MatchHost("example.org"))
}

// 8-character hash (legacy mode)
func TestSafeBrowsingEngineLegacy(t *testing.T) {
	configText := `dnsfilter {
		safebrowsing ../tests/sb.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	hash0 := sha256.Sum256([]byte("asdf.testsb.example.org"))
	q0 := hex.EncodeToString(hash0[0:4])
	hash1 := sha256.Sum256([]byte("testsb.example.org"))
	q1 := hex.EncodeToString(hash1[0:4])
	hash2 := sha256.Sum256([]byte("example.org"))
	q2 := hex.EncodeToString(hash2[0:4])
	result, _ := p.getSafeBrowsingEngine().data.MatchHashes(q0 + "." + q1 + "." + q2)
	assert.True(t, len(result) == 1)
	shash := hex.EncodeToString(hash1[:])
	assert.True(t, result[0] == shash)

	assert.True(t, p.getSafeBrowsingEngine().data.MatchHost("testsb.example.org"))
	assert.True(t, !p.getSafeBrowsingEngine().data.MatchHost("example.org"))
}

func TestSafeBrowsingFilter(t *testing.T) {
	configText := `dnsfilter {
		safebrowsing ../tests/sb.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	req := new(dns.Msg)
	req.SetQuestion("testsb.example.org.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assertResponseIP(t, rrw.Msg, "example.net")
}

// Send a TXT request with a hash prefix, receive response and find the target hash there
func TestSafeBrowsingFilterTXT(t *testing.T) {
	configText := `dnsfilter {
		safebrowsing ../tests/sb.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	hash := sha256.Sum256([]byte("testsb.example.org"))
	q := hex.EncodeToString(hash[0:2])

	req := new(dns.Msg)
	req.SetQuestion(q+sbTXTSuffix+".", dns.TypeTXT)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assertResponseTXT(t, rrw.Msg, hex.EncodeToString(hash[:]))
}

func TestParentalEngine(t *testing.T) {
	configText := `dnsfilter {
		parental ../tests/parental.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	hash0 := sha256.Sum256([]byte("asdf.testparental.example.org"))
	q0 := hex.EncodeToString(hash0[0:2])
	hash1 := sha256.Sum256([]byte("testparental.example.org"))
	q1 := hex.EncodeToString(hash1[0:2])
	hash2 := sha256.Sum256([]byte("example.org"))
	q2 := hex.EncodeToString(hash2[0:2])
	result, _ := p.getParentalEngine().data.MatchHashes(q0 + "." + q1 + "." + q2)
	assert.True(t, len(result) == 1)
	shash := hex.EncodeToString(hash1[:])
	assert.True(t, result[0] == shash)

	assert.True(t, p.getParentalEngine().data.MatchHost("testparental.example.org"))
	assert.True(t, !p.getParentalEngine().data.MatchHost("example.org"))
}

func TestParentalFilter(t *testing.T) {
	configText := `dnsfilter {
		parental ../tests/parental.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	req := new(dns.Msg)
	req.SetQuestion("testparental.example.org.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assertResponseIP(t, rrw.Msg, "example.net")
}

// Send a TXT request with a hash prefix, receive response and find the target hash there
func TestParentalFilterTXT(t *testing.T) {
	configText := `dnsfilter {
		parental ../tests/parental.txt example.net
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = zeroTTLBackend()
	ctx := context.TODO()

	hash := sha256.Sum256([]byte("testparental.example.org"))
	q := hex.EncodeToString(hash[0:2])

	req := new(dns.Msg)
	req.SetQuestion(q+pcTXTSuffix+".", dns.TypeTXT)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assertResponseTXT(t, rrw.Msg, hex.EncodeToString(hash[:]))
}

// 'badhost' has a canonical name 'badhost.eulerian.net' which is blocked by filters
func TestCNAMEFilter(t *testing.T) {
	configText := `dnsfilter {
		filter ../tests/dns.txt
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = backendCNAME()
	ctx := context.TODO()

	req := new(dns.Msg)
	req.SetQuestion("badhost.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assert.True(t, len(rrw.Msg.Answer) != 0)
	haveA := false
	for _, rec := range rrw.Msg.Answer {
		if a, ok := rec.(*dns.A); ok {
			haveA = true
			assert.True(t, a.A.Equal(net.IP{0, 0, 0, 0}))
		}
	}
	assert.True(t, haveA)
}

// 'badhost' has an IP '37.220.26.135' which is blocked by filters
func TestResponseFilter(t *testing.T) {
	configText := `dnsfilter {
		filter ../tests/dns.txt
	}`
	c := caddy.NewTestController("dns", configText)
	c.ServerBlockKeys = []string{""}
	p, err := setupPlugin(c)
	if err != nil {
		t.Fatal(err)
	}

	p.Next = backendBlockByIP()
	ctx := context.TODO()

	req := new(dns.Msg)
	req.SetQuestion("badhost.", dns.TypeA)

	resp := test.ResponseWriter{}
	rrw := dnstest.NewRecorder(&resp)
	rcode, err := p.ServeDNS(ctx, rrw, req)
	if err != nil {
		t.Fatalf("ServeDNS returned error: %s", err)
	}
	if rcode != rrw.Rcode {
		t.Fatalf("ServeDNS return value %d that does not match captured rcode %d", rcode, rrw.Rcode)
	}

	assert.True(t, len(rrw.Msg.Answer) != 0)
	haveA := false
	for _, rec := range rrw.Msg.Answer {
		if a, ok := rec.(*dns.A); ok {
			haveA = true
			assert.True(t, a.A.Equal(net.IP{0, 0, 0, 0}))
		}
	}
	assert.True(t, haveA)
}

func assertResponseIP(t *testing.T, m *dns.Msg, expectedHost string) {
	addrs, _ := net.LookupIP(expectedHost)

	if len(m.Answer) == 0 {
		t.Fatalf("no answer instead of %s", expectedHost)
	}

	for _, rec := range m.Answer {
		if a, ok := rec.(*dns.A); ok {
			for _, ip := range addrs {
				if ip.Equal(a.A) {
					// Found matching IP, all good
					return
				}
			}
		}
	}

	t.Fatalf("could not find %s IP addresses", expectedHost)
}

func assertResponseTXT(t *testing.T, m *dns.Msg, hash string) {
	for _, rec := range m.Answer {
		if txt, ok := rec.(*dns.TXT); ok {
			for _, t := range txt.Txt {
				if t == hash {
					return
				}
			}
		}
	}

	t.Fatalf("invalid TXT response")
}

func zeroTTLBackend() plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Response, m.RecursionAvailable = true, true

		m.Answer = []dns.RR{test.A("example.org. 0 IN A 127.0.0.53")}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})
}

// Return response with CNAME and A records
func backendCNAME() plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Response, m.RecursionAvailable = true, true

		m.Answer = []dns.RR{
			test.CNAME("badhost. 0 IN CNAME badhost.eulerian.net."),
			test.A("badhost.eulerian.net. 0 IN A 127.0.0.53"),
		}
		_ = w.WriteMsg(m)
		return dns.RcodeSuccess, nil
	})
}

// Return response with an A record
func backendBlockByIP() plugin.Handler {
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
