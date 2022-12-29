package dnscheck_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	randomid    = "randomid"
	checkDomain = "example.local"
	reqFQDN     = "example.org."
)

func TestNewConsul(t *testing.T) {
	testCases := []struct {
		conf       *dnscheck.ConsulConfig
		name       string
		wantErrMsg string
	}{{
		conf: &dnscheck.ConsulConfig{
			ConsulKVURL:      &url.URL{Path: "kv/test"},
			ConsulSessionURL: &url.URL{},
		},
		name:       "correct",
		wantErrMsg: ``,
	}, {
		conf:       &dnscheck.ConsulConfig{ConsulSessionURL: &url.URL{}},
		name:       "no_kv_url",
		wantErrMsg: ``,
	}, {
		conf:       &dnscheck.ConsulConfig{ConsulKVURL: &url.URL{}},
		name:       "no_session_url",
		wantErrMsg: ``,
	}, {
		conf: &dnscheck.ConsulConfig{
			ConsulKVURL:      &url.URL{Path: "kv"},
			ConsulSessionURL: &url.URL{},
		},
		name:       "few_parts",
		wantErrMsg: `initializing consul dnscheck: consul url: path "kv": too few parts`,
	}, {
		conf: &dnscheck.ConsulConfig{
			ConsulKVURL:      &url.URL{Path: "kv/"},
			ConsulSessionURL: &url.URL{},
		},
		name:       "empty_last",
		wantErrMsg: `initializing consul dnscheck: consul url: path "kv/": last part is empty`,
	}, {
		conf: &dnscheck.ConsulConfig{
			ConsulKVURL:      &url.URL{Path: "not-kv/test"},
			ConsulSessionURL: &url.URL{},
		},
		name: "wrong_part",
		wantErrMsg: `initializing consul dnscheck: consul url: path "not-kv/test": ` +
			`next to last part is "not-kv", want "kv"`,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := dnscheck.NewConsul(tc.conf)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

// jobj is a convenient alias for map to unmarshal JSON into.
type jobj = map[string]any

func TestConsul_ServeHTTP(t *testing.T) {
	theOnlyVal := jobj{
		"device_id":         "some-device-id",
		"profile_id":        "some-profile-id",
		"server_group_name": "some-server-group-name",
		"server_name":       "some-server-name",
		"protocol":          agd.ProtoDNS.String(),
		"node_location":     "some-node-location",
		"node_name":         "some-node-name",
		"client_ip":         "1.2.3.4",
	}

	conf := &dnscheck.ConsulConfig{
		Messages: &dnsmsg.Constructor{},
		ErrColl: &agdtest.ErrorCollector{
			OnCollect: func(_ context.Context, err error) { panic(err) },
		},
		Domains:      []string{checkDomain},
		NodeLocation: theOnlyVal["node_location"].(string),
		NodeName:     theOnlyVal["node_name"].(string),
		TTL:          1 * time.Minute,
	}
	dnsCk, err := dnscheck.NewConsul(conf)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
		Name:  theOnlyVal["server_name"].(string),
		Proto: agd.ProtoDNS,
	})

	var resp *dns.Msg
	resp, err = dnsCk.Check(
		ctx,
		&dns.Msg{
			Question: []dns.Question{{
				Qtype: dns.TypeA,
			}},
		},
		&agd.RequestInfo{
			Device:      &agd.Device{ID: agd.DeviceID(theOnlyVal["device_id"].(string))},
			Profile:     &agd.Profile{ID: agd.ProfileID(theOnlyVal["profile_id"].(string))},
			ServerGroup: agd.ServerGroupName(theOnlyVal["server_group_name"].(string)),
			Server:      agd.ServerName(theOnlyVal["server_name"].(string)),
			Host:        randomid + "-" + checkDomain,
			RemoteIP:    testRemoteIP,
			QType:       dns.TypeA,
		},
	)
	require.NoError(t, err)

	assert.Empty(t, resp.Answer)

	t.Run("hit", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, (&url.URL{
			Scheme: "http",
			Host:   randomid + "-" + checkDomain,
			Path:   "/dnscheck/test",
		}).String(), strings.NewReader(""))
		rw := httptest.NewRecorder()

		dnsCk.ServeHTTP(rw, r)
		assert.Equal(t, http.StatusOK, rw.Code)

		bodyJobj := jobj{}
		require.NoError(t, json.NewDecoder(rw.Body).Decode(&bodyJobj))

		assert.Equal(t, theOnlyVal, bodyJobj)
	})

	t.Run("miss", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, (&url.URL{
			Scheme: "http",
			Host:   "non" + randomid + "-" + checkDomain,
			Path:   "/dnscheck/test",
		}).String(), strings.NewReader(""))
		rw := httptest.NewRecorder()

		dnsCk.ServeHTTP(rw, r)
		assert.Equal(t, http.StatusNotFound, rw.Code)
	})
}

func TestConsul_Check(t *testing.T) {
	const ttl = 60

	testCases := []struct {
		name      string
		host      string
		wantAns   []dns.RR
		wantRcode int
		qtype     uint16
	}{{
		name: "a",
		host: randomid + "-" + checkDomain,
		wantAns: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{
				Name:     reqFQDN,
				Rrtype:   dns.TypeA,
				Class:    dns.ClassINET,
				Ttl:      ttl,
				Rdlength: 0,
			},
			A: net.IP{1, 2, 3, 4},
		}},
		wantRcode: dns.RcodeSuccess,
		qtype:     dns.TypeA,
	}, {
		name: "aaaa",
		host: randomid + "-" + checkDomain,
		wantAns: []dns.RR{&dns.AAAA{
			Hdr: dns.RR_Header{
				Name:     reqFQDN,
				Rrtype:   dns.TypeAAAA,
				Class:    dns.ClassINET,
				Ttl:      ttl,
				Rdlength: 0,
			},
			AAAA: net.ParseIP("1234::5678"),
		}},
		wantRcode: dns.RcodeSuccess,
		qtype:     dns.TypeAAAA,
	}, {
		name:      "dnskey",
		host:      ".",
		wantAns:   nil,
		wantRcode: -1,
		qtype:     dns.TypeDNSKEY,
	}, {
		name:      "any_nodata",
		host:      randomid + "-" + checkDomain,
		wantAns:   nil,
		wantRcode: dns.RcodeSuccess,
		qtype:     dns.TypeCNAME,
	}}

	conf := &dnscheck.ConsulConfig{
		Messages: &dnsmsg.Constructor{
			FilteredResponseTTL: ttl * time.Second,
		},
		Domains: []string{checkDomain},
		IPv4:    []net.IP{{1, 2, 3, 4}},
		IPv6:    []net.IP{net.ParseIP("1234::5678")},
	}

	dnsCk, err := dnscheck.NewConsul(conf)
	require.NoError(t, err)

	ctx := context.Background()
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{
		Name:  "test-server-name",
		Proto: agd.ProtoDNS,
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:  reqFQDN,
					Qtype: tc.qtype,
				}},
			}
			ri := &agd.RequestInfo{
				Host:     tc.host,
				RemoteIP: testRemoteIP,
				QType:    tc.qtype,
				Messages: &dnsmsg.Constructor{
					FilteredResponseTTL: ttl * time.Second,
				},
			}

			resp, cErr := dnsCk.Check(ctx, req, ri)
			require.NoError(t, cErr)

			if tc.wantRcode >= 0 {
				require.NotNil(t, resp)

				assert.Equal(t, tc.wantRcode, resp.Rcode)
				assert.Equal(t, tc.wantAns, resp.Answer)
			} else {
				require.Nil(t, resp)
			}
		})
	}
}
