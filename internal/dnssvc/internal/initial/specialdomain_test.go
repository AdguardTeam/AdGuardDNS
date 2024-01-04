package initial_test

import (
	"context"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_ServeDNS_specialDomain(t *testing.T) {
	testCases := []struct {
		name          string
		host          string
		qtype         dnsmsg.RRType
		fltGrpBlocked bool
		hasProf       bool
		profBlocked   bool
		wantRCode     dnsmsg.RCode
	}{{
		name:          "private_relay_blocked_by_fltgrp",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "no_special_domain",
		host:          "www.example.com",
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "no_private_relay_qtype",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeTXT,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_blocked_by_prof",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "private_relay_allowed_by_prof",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_allowed_by_both",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "private_relay_blocked_by_both",
		host:          initial.ApplePrivateRelayMaskHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeNameError,
	}, {
		name:          "firefox_canary_allowed_by_prof",
		host:          initial.FirefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "firefox_canary_allowed_by_fltgrp",
		host:          initial.FirefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeSuccess,
	}, {
		name:          "firefox_canary_blocked_by_prof",
		host:          initial.FirefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: false,
		hasProf:       true,
		profBlocked:   true,
		wantRCode:     dns.RcodeRefused,
	}, {
		name:          "firefox_canary_blocked_by_fltgrp",
		host:          initial.FirefoxCanaryHost,
		qtype:         dns.TypeA,
		fltGrpBlocked: true,
		hasProf:       false,
		profBlocked:   false,
		wantRCode:     dns.RcodeRefused,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var handler dnsserver.Handler = dnsserver.HandlerFunc(func(
				ctx context.Context,
				rw dnsserver.ResponseWriter,
				req *dns.Msg,
			) (err error) {
				if tc.wantRCode != dns.RcodeSuccess {
					return errors.Error("unexpectedly reached handler")
				}

				resp := (&dns.Msg{}).SetReply(req)

				return rw.WriteMsg(ctx, req, resp)
			})

			onProfileByLinkedIP := func(
				_ context.Context,
				_ netip.Addr,
			) (p *agd.Profile, d *agd.Device, err error) {
				if !tc.hasProf {
					return nil, nil, profiledb.ErrDeviceNotFound
				}

				prof := &agd.Profile{
					Access:             access.EmptyProfile{},
					BlockPrivateRelay:  tc.profBlocked,
					BlockFirefoxCanary: tc.profBlocked,
				}

				return prof, &agd.Device{}, nil
			}

			db := &agdtest.ProfileDB{
				OnProfileByDeviceID: func(
					_ context.Context,
					_ agd.DeviceID,
				) (p *agd.Profile, d *agd.Device, err error) {
					panic("not implemented")
				},
				OnProfileByDedicatedIP: func(
					_ context.Context,
					_ netip.Addr,
				) (p *agd.Profile, d *agd.Device, err error) {
					return nil, nil, profiledb.ErrDeviceNotFound
				},
				OnProfileByLinkedIP: onProfileByLinkedIP,
			}

			geoIP := &agdtest.GeoIP{
				OnSubnetByLocation: func(
					_ *geoip.Location,
					_ netutil.AddrFamily,
				) (n netip.Prefix, err error) {
					panic("not implemented")
				},
				OnData: func(_ string, _ netip.Addr) (l *geoip.Location, err error) {
					return nil, nil
				},
			}

			errColl := &agdtest.ErrorCollector{
				OnCollect: func(_ context.Context, _ error) {
					panic("not implemented")
				},
			}

			mw := initial.New(&initial.Config{
				Messages: agdtest.NewConstructor(),
				FilteringGroup: &agd.FilteringGroup{
					BlockPrivateRelay:  tc.fltGrpBlocked,
					BlockFirefoxCanary: tc.fltGrpBlocked,
				},
				ServerGroup: &agd.ServerGroup{},
				Server: &agd.Server{
					Protocol:        agd.ProtoDNS,
					LinkedIPEnabled: true,
				},
				ProfileDB: db,
				GeoIP:     geoIP,
				ErrColl:   errColl,
			})

			h := mw.Wrap(handler)

			ctx := context.Background()
			rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.RemoteAddr)
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   dns.Fqdn(tc.host),
					Qtype:  tc.qtype,
					Qclass: dns.ClassINET,
				}},
			}

			err := h.ServeDNS(ctx, rw, req)
			require.NoError(t, err)

			resp := rw.Msg()
			require.NotNil(t, resp)

			assert.Equal(t, tc.wantRCode, dnsmsg.RCode(resp.Rcode))
		})
	}
}
