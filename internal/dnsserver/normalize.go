package dnsserver

import "github.com/miekg/dns"

// normalize adds an OPT record that the reflects the intent from request.
// It also truncates the response if needed. The parameter network can be
// either NetworkTCP or NetworkUDP.
func normalize(network Network, req, resp *dns.Msg) {
	o := req.IsEdns0()
	if o == nil {
		truncate(resp, dnsSize(network, req))
		resp.Compress = true
		return
	}

	if mo := resp.IsEdns0(); mo != nil {
		mo.Hdr.Name = "."
		mo.Hdr.Rrtype = dns.TypeOPT
		mo.SetVersion(0)
		mo.SetUDPSize(o.UDPSize())

		// OPT record allows storing additional info in the TTL field:
		// https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
		// We don't use it so we we should clear it.
		mo.Hdr.Ttl &= 0xff00

		// Assume if the message req has options set, they are OK and represent
		// what an upstream can do.
		if o.Do() {
			mo.SetDo()
		}
		return
	}

	// Reuse the request's OPT record and tack it to m.
	o.Hdr.Name = "."
	o.Hdr.Rrtype = dns.TypeOPT
	o.SetVersion(0)
	o.Hdr.Ttl &= 0xff00 // clear flags
	o.Option = filterUsupportedOptions(o.Option)

	resp.Extra = append(resp.Extra, o)
	truncate(resp, dnsSize(network, req))

	// Always compress the response
	resp.Compress = true
}

// truncate truncates the response if needed.
func truncate(resp *dns.Msg, size int) {
	resp.Truncate(size)

	// Remove all A records from a truncated response
	// This is safer option for a public DNS resolver
	if resp.Truncated {
		resp.Answer = nil
	}
}

// dnsSize returns the buffer size *advertised* in the requests OPT record.
// Or when the request was over TCP, we return the maximum allowed size of 64K.
// network can be either "tcp" or "udp".
func dnsSize(network Network, r *dns.Msg) (n int) {
	var size uint16
	if o := r.IsEdns0(); o != nil {
		size = o.UDPSize()
	}

	if network != NetworkUDP {
		return dns.MaxMsgSize
	}

	if size < dns.MinMsgSize {
		return dns.MinMsgSize
	}

	// normalize size
	return int(size)
}

// filterUsupportedOptions filters out unsupported EDNS0 options.  The supported
// options are:
//
//   - EDNS0NSID
//   - EDNS0EXPIRE
//   - EDNS0TCPKEEPALIVE
//   - EDNS0PADDING
//
// A server that doesn't support DNS Cookies should ignore the presence of a
// COOKIE option and respond as if the request has no COOKIE option at all.
//
// See https://datatracker.ietf.org/doc/html/rfc7873#section-5.2.
func filterUsupportedOptions(o []dns.EDNS0) (supported []dns.EDNS0) {
	for _, opt := range o {
		switch code := opt.Option(); code {
		case dns.EDNS0NSID,
			dns.EDNS0EXPIRE,
			dns.EDNS0TCPKEEPALIVE,
			dns.EDNS0PADDING:
			supported = append(supported, opt)
		}
	}
	return supported
}
