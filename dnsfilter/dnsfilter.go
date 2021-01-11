package dnsfilter

import (
	"fmt"
	"strings"
	"time"

	safeservices "github.com/AdguardTeam/AdGuardDNS/dnsfilter/safe_services"
	"github.com/AdguardTeam/urlfilter/rules"

	"github.com/AdguardTeam/urlfilter"

	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
)

const NotFiltered = -100

// https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https
const FirefoxCanaryDomain = "use-application-dns.net"
const sbTXTSuffix = ".sb.dns.adguard.com"
const pcTXTSuffix = ".pc.dns.adguard.com"

// ServeDNS handles the DNS request and refuses if it's in filterlists
func (p *plug) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if len(r.Question) != 1 {
		// google DNS, bind and others do the same
		return dns.RcodeFormatError, fmt.Errorf("got a DNS request with more than one Question")
	}

	// measure time spent in dnsfilter
	start := time.Now()

	rcode, err := p.handleTXT(ctx, w, r)
	if rcode == NotFiltered {
		// pass the request to an upstream server and receive response
		rec := responseRecorder{
			ResponseWriter: w,
		}
		rcode, err = plugin.NextOrFailure(p.Name(), p.Next, ctx, &rec, r)

		// measure time spent in dnsfilter
		startFiltering := time.Now()

		if err == nil && rec.resp != nil {
			// check if request or response should be blocked
			rcode2, err2 := p.filterRequest(ctx, w, r, rec.resp)
			if rcode2 != NotFiltered {
				incFiltered(w)
				rcode = rcode2
				err = err2
				rec.resp = nil // filterRequest() has already written the response
			}

			elapsedFilterTime.Observe(time.Since(startFiltering).Seconds())
		}
		if rec.resp != nil {
			err2 := w.WriteMsg(rec.resp) // pass through the original response
			if err == nil {
				err = err2
			}
		}
	}

	// increment requests counters
	incRequests(w)
	elapsedTime.Observe(time.Since(start).Seconds())

	if err != nil {
		errorsTotal.Inc()
	}

	return rcode, err
}

// Stores DNS response object
type responseRecorder struct {
	dns.ResponseWriter
	resp *dns.Msg
}

func (r *responseRecorder) WriteMsg(res *dns.Msg) error {
	r.resp = res
	return nil
}

func (p *plug) replyTXT(w dns.ResponseWriter, r *dns.Msg, txtData []string) error {
	txt := dns.TXT{}
	txt.Hdr = dns.RR_Header{
		Name:   r.Question[0].Name,
		Rrtype: dns.TypeTXT,
		Ttl:    p.settings.BlockedTTL,
		Class:  dns.ClassINET,
	}
	txt.Txt = txtData
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.RecursionAvailable = true
	m.Compress = true
	m.Answer = append(m.Answer, &txt)

	state := request.Request{W: w, Req: r}
	state.SizeAndDo(m)
	return state.W.WriteMsg(m)
}

// Respond to TXT requests for safe-browsing and parental services.
// Return NotFiltered if request wasn't handled.
func (p *plug) handleTXT(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	host := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))

	if p.settings.SafeBrowsingEnabled &&
		r.Question[0].Qtype == dns.TypeTXT &&
		strings.HasSuffix(host, sbTXTSuffix) {

		requestsSafeBrowsingTXT.Inc()

		hashStr := host[:len(host)-len(sbTXTSuffix)]
		txtData, _ := p.getSafeBrowsingEngine().data.MatchHashes(hashStr)
		err := p.replyTXT(w, r, txtData)
		if err != nil {
			clog.Infof("SafeBrowsing: WriteMsg(): %s\n", err)
			return dns.RcodeServerFailure, fmt.Errorf("SafeBrowsing: WriteMsg(): %s", err)
		}
		return dns.RcodeSuccess, nil
	}

	if p.settings.ParentalEnabled &&
		r.Question[0].Qtype == dns.TypeTXT &&
		strings.HasSuffix(host, pcTXTSuffix) {

		requestsParentalTXT.Inc()

		hashStr := host[:len(host)-len(pcTXTSuffix)]
		txtData, _ := p.getParentalEngine().data.MatchHashes(hashStr)
		err := p.replyTXT(w, r, txtData)
		if err != nil {
			clog.Infof("Parental: WriteMsg(): %s\n", err)
			return dns.RcodeServerFailure, fmt.Errorf("parental: WriteMsg(): %s", err)
		}
		return dns.RcodeSuccess, nil
	}

	return NotFiltered, nil
}

// filterRequest applies dnsfilter rules to the request. If the request should be blocked,
// it writes the response right away. Otherwise, it returns NotFiltered instead of the response code,
// which means that the request should processed further by the next plugins in the chain.
func (p *plug) filterRequest(ctx context.Context, w dns.ResponseWriter, req *dns.Msg, res *dns.Msg) (int, error) {
	question := req.Question[0]
	host := strings.ToLower(strings.TrimSuffix(question.Name, "."))

	if (question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA) &&
		host == FirefoxCanaryDomain {
		return p.writeNXDomain(ctx, w, req)
	}

	// is it a safesearch domain?
	if p.settings.SafeSearchEnabled {
		if replacementHost, ok := safeservices.SafeSearchDomains[host]; ok {
			safeSearch.Inc()

			return p.replaceHostWithValAndReply(ctx, w, req, host, replacementHost, question)
		}
	}

	// is it blocked by safebrowsing?
	if p.settings.SafeBrowsingEnabled && p.getSafeBrowsingEngine().data.MatchHost(host) {
		filteredSafeBrowsing.Inc()

		// return cname safebrowsing.block.dns.adguard.com
		replacementHost := p.settings.SafeBrowsingBlockHost
		return p.replaceHostWithValAndReply(ctx, w, req, host, replacementHost, question)
	}

	// is it blocked by parental control?
	if p.settings.ParentalEnabled && p.getParentalEngine().data.MatchHost(host) {
		filteredParental.Inc()

		// return cname family.block.dns.adguard.com
		replacementHost := p.settings.ParentalBlockHost
		return p.replaceHostWithValAndReply(ctx, w, req, host, replacementHost, question)
	}

	// is it blocked by filtering rules
	ok, rule := p.matchesEngine(p.getBlockingEngine(), host, true)
	if ok {
		filteredLists.Inc()
		return p.writeBlacklistedResponse(ctx, w, req)
	}

	if rule != nil {
		if f, ok := rule.(*rules.NetworkRule); ok {
			if f.Whitelist {
				// Do nothing if this is a whitelist rule
				return NotFiltered, nil
			}
		}
	}

	// try checking DNS response now
	matched, rcode, err := p.filterResponse(ctx, w, req, res)
	if matched {
		return rcode, err
	}

	// indicate that the next plugin must be called
	return NotFiltered, nil
}

// If response contains CNAME, A or AAAA records, we apply filtering to each canonical host name or IP address.
func (p *plug) filterResponse(ctx context.Context, w dns.ResponseWriter, req *dns.Msg, resp *dns.Msg) (bool, int, error) {
	for _, a := range resp.Answer {
		host := ""

		switch v := a.(type) {
		case *dns.CNAME:
			clog.Debugf("Checking CNAME %s for %s", v.Target, v.Hdr.Name)
			host = strings.TrimSuffix(v.Target, ".")

		case *dns.A:
			host = v.A.String()
			clog.Debugf("Checking record A (%s) for %s", host, v.Hdr.Name)

		case *dns.AAAA:
			host = v.AAAA.String()
			clog.Debugf("Checking record AAAA (%s) for %s", host, v.Hdr.Name)

		default:
			continue
		}

		if ok, _ := p.matchesEngine(p.getBlockingEngine(), host, true); ok {
			clog.Debugf("Matched %s by response: %s", req.Question[0].Name, host)
			filteredLists.Inc()
			rcode, err := p.writeBlacklistedResponse(ctx, w, req)
			return true, rcode, err
		}
	}

	return false, 0, nil
}

// matchesEngine checks if there's a match for the specified host
// note, that if it matches a whitelist rule, the function returns false
// recordStats -- if true, we record hit for the matching rule
// returns true if request should be blocked
func (p *plug) matchesEngine(engine *urlfilter.DNSEngine, host string, recordStats bool) (bool, rules.Rule) {
	if engine == nil {
		return false, nil
	}

	res, ok := engine.Match(host, nil)
	if !ok {
		return false, nil
	}

	if res.NetworkRule != nil {
		if recordStats {
			recordRuleHit(res.NetworkRule.RuleText)
		}

		if res.NetworkRule.Whitelist {
			return false, res.NetworkRule
		}

		return true, res.NetworkRule
	}

	var matchingRule rules.Rule
	if len(res.HostRulesV4) > 0 {
		matchingRule = res.HostRulesV4[0]
	} else if len(res.HostRulesV6) > 0 {
		matchingRule = res.HostRulesV6[0]
	} else {
		return false, nil
	}

	if recordStats {
		recordRuleHit(matchingRule.Text())
	}

	return true, matchingRule
}
