// Package info is a CoreDNS plugin for testing users' DNS settings.
package info

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/util"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
)

type info struct {
	Next plugin.Handler

	domain     string // etld domain name for the check DNS requests
	protocol   string // protocol (can be auto, dns, doh, doq, dot, dnscrypt)
	serverType string // server type (arbitrary string)
	canary     string // canary domain

	addrs4 []net.IP // list of IPv4 addresses to return in response to an A check request
	addrs6 []net.IP // list of IPv4 addresses to return in response to an AAAA check request
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (i *info) Name() string { return "info" }

// ServeDNS handles the DNS request and refuses if it's an ANY request
func (i *info) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		// google DNS, bind and others do the same
		return dns.RcodeFormatError, fmt.Errorf("got DNS request with != 1 questions")
	}

	question := r.Question[0]
	host := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	if i.canary != "" && host == i.canary {
		return i.writeAnswer(w, r)
	}

	protocol := i.getProtocol(ctx)
	checkDomain := fmt.Sprintf("-%s-%s-dnscheck.%s", protocol, i.serverType, i.domain)

	if strings.HasSuffix(host, checkDomain) {
		return i.writeAnswer(w, r)
	}

	return plugin.NextOrFailure(i.Name(), i.Next, ctx, w, r)
}

func (i *info) getProtocol(ctx context.Context) string {
	if i.protocol == "auto" {
		addr := util.GetServer(ctx)
		if strings.HasPrefix(addr, "tls") {
			return "dot"
		} else if strings.HasPrefix(addr, "https") {
			return "doh"
		} else if strings.HasPrefix(addr, "quic") {
			return "doq"
		}

		return "dns"
	}

	return i.protocol
}

func (i *info) writeAnswer(w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	m := i.genAnswer(r)

	state.SizeAndDo(m)
	err := state.W.WriteMsg(m)
	if err != nil {
		clog.Infof("Got error %s\n", err)
		return dns.RcodeServerFailure, err
	}
	return m.Rcode, nil
}

func (i *info) genAnswer(r *dns.Msg) *dns.Msg {
	m := new(dns.Msg)
	m.SetRcode(r, dns.RcodeSuccess)

	qType := r.Question[0].Qtype

	if qType == dns.TypeA && len(i.addrs4) > 0 {
		for _, ip := range i.addrs4 {
			m.Answer = append(m.Answer, i.genA(r, ip))
		}
	} else if qType == dns.TypeAAAA && len(i.addrs6) > 0 {
		for _, ip := range i.addrs6 {
			m.Answer = append(m.Answer, i.genAAAA(r, ip))
		}
	}

	m.RecursionAvailable = true
	m.Compress = true

	return m
}

func (i *info) genA(r *dns.Msg, ip net.IP) *dns.A {
	answer := new(dns.A)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeA,
		Ttl:    100,
		Class:  dns.ClassINET,
	}
	answer.A = ip
	return answer
}

func (i *info) genAAAA(r *dns.Msg, ip net.IP) *dns.AAAA {
	answer := new(dns.AAAA)
	answer.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeAAAA,
		Ttl:    100,
		Class:  dns.ClassINET,
	}
	answer.AAAA = ip
	return answer
}
