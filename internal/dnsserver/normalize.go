package dnsserver

import (
	"math/rand"

	"github.com/miekg/dns"
)

// responsePaddingMaxSize is used to calculate the EDNS padding length.  We use
// the Random-Length Padding strategy from RFC 8467 as we find it more
// efficient, it requires less extra traffic while provides comparable entropy.
const responsePaddingMaxSize = 32

// respPadBuf is a fixed buffer to draw on for padding.
var respPadBuf [responsePaddingMaxSize]byte

// normalize adds an OPT record that the reflects the intent from request.
// It also truncates the response and pads response if needed.
//
// TODO(ameshkov): Consider adding EDNS0COOKIE support.
func normalize(network Network, proto Protocol, req, resp *dns.Msg) {
	reqOpt := req.IsEdns0()
	if reqOpt == nil {
		truncate(resp, dnsSize(network, req))
		resp.Compress = true

		return
	}

	var respOpt *dns.OPT
	if respOpt = resp.IsEdns0(); respOpt != nil {
		respOpt.Hdr.Name = "."
		respOpt.Hdr.Rrtype = dns.TypeOPT
		respOpt.SetVersion(0)
		respOpt.SetUDPSize(reqOpt.UDPSize())

		// OPT record allows storing additional info in the TTL field:
		// https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.3
		// We don't use it so we should clear it.
		respOpt.Hdr.Ttl &= 0xff00

		// Assume if the message req has options set, they are OK and represent
		// what an upstream can do.
		if reqOpt.Do() {
			respOpt.SetDo()
		}
	} else {
		// Reuse the request's OPT record options and tack it to resp.
		respOpt = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
			Option: filterUnsupportedOptions(reqOpt.Option),
		}
		resp.Extra = append(resp.Extra, respOpt)
	}

	// Make sure that we don't send messages larger than the protocol supports.
	truncate(resp, dnsSize(network, req))

	// Always compress the response.
	resp.Compress = true

	// In the case of encrypted protocols we should pad responses.
	if proto.HasPaddingSupport() {
		padAnswer(reqOpt, respOpt)
	}
}

// truncate makes sure the response is not larger than the specified size.  If
// it is, the Truncate flag is set to true and answer records are removed.
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

// filterUnsupportedOptions filters out unsupported EDNS0 options.  The
// supported options are:
//
//   - EDNS0NSID
//   - EDNS0EXPIRE
//
// All other options will be removed from the resulting array.
func filterUnsupportedOptions(o []dns.EDNS0) (supported []dns.EDNS0) {
	for _, opt := range o {
		switch code := opt.Option(); code {
		case dns.EDNS0NSID,
			dns.EDNS0EXPIRE:
			supported = append(supported, opt)
		}
	}

	return supported
}

// padAnswer adds padding to a DNS response before it's sent back over an
// encrypted DNS protocol according to RFC 8467.  Unencrypted responses should
// not be padded.  Inspired by github.com/folbricht/routedns padding.
func padAnswer(reqOpt, respOpt *dns.OPT) {
	if findOption[*dns.EDNS0_PADDING](reqOpt) == nil {
		// According to the RFC, responders MAY (or may not) pad responses when
		// the padding option is not included in the request.  In our case, we
		// don't pad every response unless the client indicates that we must.

		return
	}

	// If the answer has padding, grab that and truncate it before recalculating
	// the length.
	paddingOpt := findOption[*dns.EDNS0_PADDING](respOpt)
	if paddingOpt != nil {
		paddingOpt.Padding = nil
	} else {
		// Add the padding option if there isn't one already.
		paddingOpt = &dns.EDNS0_PADDING{Padding: nil}
		respOpt.Option = append(respOpt.Option, paddingOpt)
	}

	// TODO(ameshkov): Consider changing to crypto/rand, need to hold a vote.
	// #nosec G404 -- We don't need a real random for a simple padding
	// randomization, pseudo-random is enough.
	//
	// Note, that we don't check for whether reqOpt.UDPSize() here is smaller
	// than resp.Len() + padLen so in theory the padded response may be larger
	// than 64kB.  This is an acceptable risk considering the savings on
	// avoiding calling resp.Len().
	//
	// TODO(ameshkov): Return this check if we optimize resp.Len().
	padLen := rand.Intn(responsePaddingMaxSize-1) + 1

	paddingOpt.Padding = respPadBuf[:padLen:padLen]
}

// findOption searches for the specified EDNS0 option in the OPT resource record
// and returns it or nil if it's not present.
//
// TODO(ameshkov): Consider moving to golibs.
func findOption[T dns.EDNS0](rr *dns.OPT) (o T) {
	for _, opt := range rr.Option {
		var ok bool
		if o, ok = opt.(T); ok {
			return o
		}
	}

	return o
}
