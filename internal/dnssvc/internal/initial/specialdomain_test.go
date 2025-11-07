package initial_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/dnssvctest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnssvc/internal/initial"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMiddleware_Wrap_specialDomain(t *testing.T) {
	var (
		profAllowed = &agd.Profile{
			Access:              access.EmptyProfile{},
			BlockChromePrefetch: false,
			BlockFirefoxCanary:  false,
			BlockPrivateRelay:   false,
		}

		profBlocked = &agd.Profile{
			Access:              access.EmptyProfile{},
			BlockChromePrefetch: true,
			BlockFirefoxCanary:  true,
			BlockPrivateRelay:   true,
		}
	)

	var (
		fltGrpAllowed = &agd.FilteringGroup{
			BlockChromePrefetch: false,
			BlockFirefoxCanary:  false,
			BlockPrivateRelay:   false,
		}

		fltGrpBlocked = &agd.FilteringGroup{
			BlockChromePrefetch: true,
			BlockFirefoxCanary:  true,
			BlockPrivateRelay:   true,
		}
	)

	const (
		appleHost   = initial.ApplePrivateRelayMaskHost
		chromeHost  = initial.ChromePrefetchHost
		firefoxHost = initial.FirefoxCanaryHost
	)

	testCases := []struct {
		reqInfo   *agd.RequestInfo
		name      string
		wantRCode dnsmsg.RCode
	}{{
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, appleHost, dns.TypeA),
		name:      "private_relay_blocked_by_fltgrp",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, dnssvctest.DomainAllowed, dns.TypeA),
		name:      "no_special_domain",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, appleHost, dns.TypeTXT),
		name:      "private_relay_blocked_txt",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, appleHost, dns.TypeCNAME),
		name:      "private_relay_blocked_cname",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, appleHost, dns.TypeHTTPS),
		name:      "private_relay_blocked_https",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profBlocked, fltGrpAllowed, appleHost, dns.TypeA),
		name:      "private_relay_blocked_by_prof",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profAllowed, fltGrpBlocked, appleHost, dns.TypeA),
		name:      "private_relay_allowed_by_prof",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profAllowed, fltGrpAllowed, appleHost, dns.TypeA),
		name:      "private_relay_allowed_by_both",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profBlocked, fltGrpAllowed, appleHost, dns.TypeA),
		name:      "private_relay_blocked_by_both",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profAllowed, fltGrpAllowed, firefoxHost, dns.TypeA),
		name:      "firefox_canary_allowed_by_prof",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpAllowed, firefoxHost, dns.TypeA),
		name:      "firefox_canary_allowed_by_fltgrp",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profBlocked, fltGrpAllowed, firefoxHost, dns.TypeA),
		name:      "firefox_canary_blocked_by_prof",
		wantRCode: dns.RcodeRefused,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, firefoxHost, dns.TypeA),
		name:      "firefox_canary_blocked_by_fltgrp",
		wantRCode: dns.RcodeRefused,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profAllowed, fltGrpAllowed, chromeHost, dns.TypeA),
		name:      "chrome_prefetch_allowed_by_both",
		wantRCode: dns.RcodeSuccess,
	}, {
		reqInfo:   newSpecDomReqInfo(t, profBlocked, fltGrpAllowed, chromeHost, dns.TypeA),
		name:      "chrome_prefetch_blocked_by_prof",
		wantRCode: dns.RcodeNameError,
	}, {
		reqInfo:   newSpecDomReqInfo(t, nil, fltGrpBlocked, chromeHost, dns.TypeA),
		name:      "chrome_prefetch_blocked_by_fltgrp",
		wantRCode: dns.RcodeNameError,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mw := initial.New(&initial.Config{
				Logger:  slogutil.NewDiscardLogger(),
				Metrics: initial.EmptyMetrics{},
				DDR: &initial.DDRConfig{
					Enabled: false,
				},
			})

			h := mw.Wrap(newSpecDomHandler(tc.wantRCode == dns.RcodeSuccess))

			ctx := testutil.ContextWithTimeout(t, dnssvctest.Timeout)
			ctx = agd.ContextWithRequestInfo(ctx, tc.reqInfo)

			rw := dnsserver.NewNonWriterResponseWriter(nil, dnssvctest.ClientTCPAddr)
			req := &dns.Msg{
				Question: []dns.Question{{
					Name:   dns.Fqdn(tc.reqInfo.Host),
					Qtype:  tc.reqInfo.QType,
					Qclass: tc.reqInfo.QClass,
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

// newSpecDomReqInfo is a helper that creates an *agd.RequestInfo from the given
// parameters.
func newSpecDomReqInfo(
	tb testing.TB,
	prof *agd.Profile,
	fltGrp *agd.FilteringGroup,
	host string,
	qtype dnsmsg.RRType,
) (ri *agd.RequestInfo) {
	tb.Helper()

	ri = &agd.RequestInfo{
		Messages:       agdtest.NewConstructor(tb),
		FilteringGroup: fltGrp,
		Host:           host,
		QClass:         dns.ClassINET,
		QType:          qtype,
	}

	if prof == nil {
		return ri
	}

	dev := &agd.Device{
		Auth: &agd.AuthSettings{
			Enabled:      false,
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
	}

	ri.DeviceResult = &agd.DeviceResultOK{
		Device:  dev,
		Profile: prof,
	}

	return ri
}

// newSpecDomHandler is a helper that creates a DNS handler for the
// special-domain tests.  The handler returns an error if wantReach is false.
func newSpecDomHandler(wantReach bool) (h dnsserver.Handler) {
	return dnsserver.HandlerFunc(func(
		ctx context.Context,
		rw dnsserver.ResponseWriter,
		req *dns.Msg,
	) (err error) {
		if !wantReach {
			return errors.Error("unexpectedly reached handler")
		}

		resp := (&dns.Msg{}).SetReply(req)

		return rw.WriteMsg(ctx, req, resp)
	})
}
