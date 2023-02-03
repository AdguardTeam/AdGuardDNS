package dnssvc

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTXTExtra is a helper function that converts strs into DNS TXT resource
// records with Name and Txt fields set to first and second values of each
// tuple.
func newTXTExtra(strs [][2]string) (extra []dns.RR) {
	for _, v := range strs {
		extra = append(extra, &dns.TXT{
			Hdr: dns.RR_Header{
				Name:   v[0],
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassCHAOS,
				Ttl:    1,
			},
			Txt: []string{v[1]},
		})
	}

	return extra
}

func TestService_writeDebugResponse(t *testing.T) {
	svc := &Service{messages: &dnsmsg.Constructor{FilteredResponseTTL: time.Second}}

	const (
		fltListID1 agd.FilterListID = "fl1"
		fltListID2 agd.FilterListID = "fl2"

		blockRule = "||example.com^"
	)

	testCases := []struct {
		name      string
		ri        *agd.RequestInfo
		reqRes    filter.Result
		respRes   filter.Result
		wantExtra []dns.RR
	}{{
		name:    "normal",
		ri:      &agd.RequestInfo{},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:    "request_result_blocked",
		ri:      &agd.RequestInfo{},
		reqRes:  &filter.ResultBlocked{List: fltListID1, Rule: blockRule},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"req.res-type.adguard-dns.com.", "blocked"},
			{"req.rule.adguard-dns.com.", "||example.com^"},
			{"req.rule-list-id.adguard-dns.com.", "fl1"},
		}),
	}, {
		name:    "response_result_blocked",
		ri:      &agd.RequestInfo{},
		reqRes:  nil,
		respRes: &filter.ResultBlocked{List: fltListID2, Rule: blockRule},
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"resp.res-type.adguard-dns.com.", "blocked"},
			{"resp.rule.adguard-dns.com.", "||example.com^"},
			{"resp.rule-list-id.adguard-dns.com.", "fl2"},
		}),
	}, {
		name:    "request_result_allowed",
		ri:      &agd.RequestInfo{},
		reqRes:  &filter.ResultAllowed{},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"req.res-type.adguard-dns.com.", "allowed"},
			{"req.rule.adguard-dns.com.", ""},
			{"req.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:    "response_result_allowed",
		ri:      &agd.RequestInfo{},
		reqRes:  nil,
		respRes: &filter.ResultAllowed{},
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"resp.res-type.adguard-dns.com.", "allowed"},
			{"resp.rule.adguard-dns.com.", ""},
			{"resp.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name: "request_result_modified",
		ri:   &agd.RequestInfo{},
		reqRes: &filter.ResultModified{
			Rule: "||example.com^$dnsrewrite=REFUSED",
		},
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"req.res-type.adguard-dns.com.", "modified"},
			{"req.rule.adguard-dns.com.", "||example.com^$dnsrewrite=REFUSED"},
			{"req.rule-list-id.adguard-dns.com.", ""},
		}),
	}, {
		name:    "device",
		ri:      &agd.RequestInfo{Device: &agd.Device{ID: "dev1234"}},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"device-id.adguard-dns.com.", "dev1234"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name: "profile",
		ri: &agd.RequestInfo{
			Profile: &agd.Profile{ID: agd.ProfileID("some-profile-id")},
		},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"profile-id.adguard-dns.com.", "some-profile-id"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}, {
		name:    "location",
		ri:      &agd.RequestInfo{Location: &agd.Location{Country: agd.CountryAD}},
		reqRes:  nil,
		respRes: nil,
		wantExtra: newTXTExtra([][2]string{
			{"client-ip.adguard-dns.com.", "1.2.3.4"},
			{"country.adguard-dns.com.", "AD"},
			{"asn.adguard-dns.com.", "0"},
			{"resp.res-type.adguard-dns.com.", "normal"},
		}),
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)

			ctx := agd.ContextWithRequestInfo(context.Background(), tc.ri)

			req := dnsservertest.NewReq("example.com", dns.TypeA, dns.ClassINET)
			resp := dnsservertest.NewResp(dns.RcodeSuccess, req)

			err := svc.writeDebugResponse(ctx, rw, req, resp, tc.reqRes, tc.respRes)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantExtra, msg.Extra)
		})
	}
}
