package dnssvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/dnsservertest"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter/hashprefix"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPreServiceMwHandler_ServeDNS(t *testing.T) {
	const safeBrowsingHost = "scam.example.net."

	var (
		ip   = net.IP{127, 0, 0, 1}
		name = "example.com"
	)

	sum := sha256.Sum256([]byte(safeBrowsingHost))
	hashStr := hex.EncodeToString(sum[:])
	host := hashStr[:hashprefix.PrefixEncLen] + filter.GeneralTXTSuffix

	ctx := context.Background()
	ctx = dnsserver.ContextWithClientInfo(ctx, dnsserver.ClientInfo{})
	ctx = dnsserver.ContextWithServerInfo(ctx, dnsserver.ServerInfo{})
	ctx = dnsserver.ContextWithStartTime(ctx, time.Now())

	const ttl = 60

	testCases := []struct {
		name         string
		req          *dns.Msg
		dnscheckResp *dns.Msg
		ri           *agd.RequestInfo
		hashes       []string
		wantAns      []dns.RR
	}{{
		name:         "normal",
		req:          dnsservertest.CreateMessage(name, dns.TypeA),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{},
		hashes:       nil,
		wantAns: []dns.RR{
			dnsservertest.NewA(name, 100, ip),
		},
	}, {
		name: "dnscheck",
		req:  dnsservertest.CreateMessage(name, dns.TypeA),
		dnscheckResp: dnsservertest.NewResp(
			dns.RcodeSuccess,
			dnsservertest.NewReq(name, dns.TypeA, dns.ClassINET),
			dnsservertest.SectionAnswer{dnsservertest.NewA(name, ttl, ip)},
		),
		ri: &agd.RequestInfo{
			Host:   name,
			QType:  dns.TypeA,
			QClass: dns.ClassINET,
		},
		hashes: nil,
		wantAns: []dns.RR{
			dnsservertest.NewA(name, ttl, ip),
		},
	}, {
		name:         "with_hashes",
		req:          dnsservertest.CreateMessage(safeBrowsingHost, dns.TypeTXT),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{Host: host, QType: dns.TypeTXT},
		hashes:       []string{hashStr},
		wantAns: []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{
				Name:   safeBrowsingHost,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: []string{hashStr},
		}},
	}, {
		name:         "not_matched",
		req:          dnsservertest.CreateMessage(name, dns.TypeTXT),
		dnscheckResp: nil,
		ri:           &agd.RequestInfo{Host: name, QType: dns.TypeTXT},
		hashes:       nil,
		wantAns:      []dns.RR{dnsservertest.NewA(name, 100, ip)},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			rw := dnsserver.NewNonWriterResponseWriter(nil, testRAddr)
			tctx := agd.ContextWithRequestInfo(ctx, tc.ri)

			dnsCk := &agdtest.DNSCheck{
				OnCheck: func(
					ctx context.Context,
					msg *dns.Msg,
					ri *agd.RequestInfo,
				) (resp *dns.Msg, err error) {
					return tc.dnscheckResp, nil
				},
			}

			hashMatcher := &agdtest.HashMatcher{
				OnMatchByPrefix: func(
					ctx context.Context,
					host string,
				) (hashes []string, matched bool, err error) {
					return tc.hashes, len(tc.hashes) > 0, nil
				},
			}

			mw := &preServiceMw{
				messages:    dnsmsg.NewConstructor(&dnsmsg.BlockingModeNullIP{}, ttl*time.Second),
				hashMatcher: hashMatcher,
				checker:     dnsCk,
			}
			handler := dnsservertest.DefaultHandler()
			h := mw.Wrap(handler)

			err := h.ServeDNS(tctx, rw, tc.req)
			require.NoError(t, err)

			msg := rw.Msg()
			require.NotNil(t, msg)

			assert.Equal(t, tc.wantAns, msg.Answer)
		})
	}
}
