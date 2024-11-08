package dnscheck_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnscheck"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/remotekv"
	"github.com/AdguardTeam/golibs/netutil/urlutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	randomid    = "randomid"
	checkDomain = "example.local"
	reqFQDN     = "example.org."
)

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
		"server_type":       "private",
	}

	conf := &dnscheck.RemoteKVConfig{
		Messages:     &dnsmsg.Constructor{},
		RemoteKV:     remotekv.Empty{},
		ErrColl:      agdtest.NewErrorCollector(),
		Domains:      []string{checkDomain},
		NodeLocation: theOnlyVal["node_location"].(string),
		NodeName:     theOnlyVal["node_name"].(string),
	}
	dnsCk := dnscheck.NewRemoteKV(conf)

	ctx := context.Background()

	var resp *dns.Msg
	resp, err := dnsCk.Check(
		ctx,
		&dns.Msg{
			Question: []dns.Question{{
				Qtype: dns.TypeA,
			}},
		},
		&agd.RequestInfo{
			DeviceResult: &agd.DeviceResultOK{
				Device:  &agd.Device{ID: agd.DeviceID(theOnlyVal["device_id"].(string))},
				Profile: &agd.Profile{ID: agd.ProfileID(theOnlyVal["profile_id"].(string))},
			},
			ServerGroup: &agd.ServerGroup{
				Name:            agd.ServerGroupName(theOnlyVal["server_group_name"].(string)),
				ProfilesEnabled: theOnlyVal["server_type"] == "private",
			},
			Server:   agd.ServerName(theOnlyVal["server_name"].(string)),
			Host:     randomid + "-" + checkDomain,
			RemoteIP: testRemoteIP,
			QType:    dns.TypeA,
			Proto:    agd.ProtoDNS,
		},
	)
	require.NoError(t, err)

	assert.Empty(t, resp.Answer)

	t.Run("hit", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, (&url.URL{
			Scheme: urlutil.SchemeHTTP,
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
			Scheme: urlutil.SchemeHTTP,
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

	msgs := agdtest.NewConstructorWithTTL(t, ttl*time.Second)

	conf := &dnscheck.RemoteKVConfig{
		Messages: msgs,
		RemoteKV: remotekv.Empty{},
		Domains:  []string{checkDomain},
		IPv4:     []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		IPv6:     []netip.Addr{netip.MustParseAddr("1234::5678")},
	}

	dnsCk := dnscheck.NewRemoteKV(conf)

	ctx := context.Background()

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:  reqFQDN,
					Qtype: tc.qtype,
				}},
			}
			ri := &agd.RequestInfo{
				Host:        tc.host,
				ServerGroup: &agd.ServerGroup{},
				RemoteIP:    testRemoteIP,
				QType:       tc.qtype,
				Messages:    msgs,
				Proto:       agd.ProtoDNS,
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
