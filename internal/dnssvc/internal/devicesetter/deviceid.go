package devicesetter

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/optlog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// supportsDeviceID returns true if p supports a way to get a device ID.
func supportsDeviceID(p agd.Protocol) (ok bool) {
	switch p {
	case
		agd.ProtoDNS,
		agd.ProtoDoH,
		agd.ProtoDoQ,
		agd.ProtoDoT:
		return true
	default:
		return false
	}
}

// deviceID extracts the device ID from the given parameters.  If the device ID
// is not found, it returns an empty ID and nil, as the lookup could also be
// done later by remote and local addresses.
func (ds *Default) deviceID(
	req *dns.Msg,
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, err error) {
	if ds.srv.Protocol.IsStdEncrypted() {
		return ds.deviceIDFromSrvReqInfo(srvReqInfo)
	}

	return deviceIDFromEDNS(req)
}

// deviceIDFromSrvReqInfo extracts device ID from the arguments.  The ID is
// extracted in the following manner:
//
//  1. If applicable, the ID is firstly extracted from the DoH information, such
//     as the userinfo or URL path.
//
//  2. Secondly, the TLS Server Name is inspected using ds's device ID
//     wildcards.
//
// Any returned errors will have the underlying type of [*deviceIDError].
func (ds *Default) deviceIDFromSrvReqInfo(
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, err error) {
	if ds.srv.Protocol == agd.ProtoDoH {
		id, err = deviceIDForDoH(srvReqInfo)
		if id != "" || err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return id, err
		}
	}

	if len(ds.wildcardDomains) == 0 {
		return "", nil
	}

	id, err = ds.deviceIDFromCliSrvName(srvReqInfo.TLSServerName)
	if err != nil {
		return "", newDeviceIDError(err, "tls server name")
	}

	return id, nil
}

// deviceIDForDoH extracts a device ID from the DoH request information.  The ID
// is extracted firstly from the request's userinfo, if any, and then from the
// URL path.  srvReqInfo must not be nil.
//
// Any returned errors will have the underlying type of [*deviceIDError].
func deviceIDForDoH(srvReqInfo *dnsserver.RequestInfo) (id agd.DeviceID, err error) {
	if userinfo := srvReqInfo.Userinfo; userinfo != nil {
		id, err = agd.NewDeviceID(userinfo.Username())
		if err != nil {
			return "", newDeviceIDError(err, "basic auth")
		}

		return id, nil
	}

	id, err = deviceIDFromDoHURL(srvReqInfo.URL)
	if err != nil {
		return "", newDeviceIDError(err, "http url path")
	}

	// In case of empty device ID, we will continue the lookup process.
	return id, nil
}

// deviceIDFromDoHURL extracts the device ID from the path of the DoH request.
func deviceIDFromDoHURL(u *url.URL) (id agd.DeviceID, err error) {
	parts, err := pathParts(u.Path)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", err
	}

	if len(parts) == 2 {
		// Don't wrap the error, because it's informative enough as is.
		return agd.NewDeviceID(parts[1])
	}

	// pathParts guarantees that if there aren't two parts, there's only one,
	// and it is a valid DNS path.
	return "", nil
}

// pathParts splits and validates urlPath.  If err is nil, parts has either one
// or two parts.
func pathParts(urlPath string) (parts []string, err error) {
	defer func() { err = errors.Annotate(err, "bad path %q: %w", urlPath) }()

	parts = strings.Split(path.Clean(urlPath), "/")
	if parts[0] == "" {
		parts = parts[1:]
	}

	l := len(parts)
	if l == 0 || parts[0] == "" {
		return nil, errors.Error("empty elements")
	} else if l > 2 {
		return nil, fmt.Errorf("%d extra parts", l-2)
	}

	if !strings.HasSuffix(dnsserver.PathDoH, parts[0]) &&
		!strings.HasSuffix(dnsserver.PathJSON, parts[0]) {
		return nil, errors.Error("not a dns path")
	}

	return parts, nil
}

// deviceIDFromCliSrvName extracts and validates a device ID.  cliSrvName is the
// server name as sent by the client.
func (ds *Default) deviceIDFromCliSrvName(cliSrvName string) (id agd.DeviceID, err error) {
	if cliSrvName == "" {
		// No server name in ClientHello, so the request is probably made on the
		// IP address.
		return "", nil
	}

	matchedDomain := matchDomain(cliSrvName, ds.wildcardDomains)
	if matchedDomain == "" {
		return "", nil
	}

	optlog.Debug2("devicesetter: device id: matched %q from %q", matchedDomain, ds.wildcardDomains)

	idStr := cliSrvName[:len(cliSrvName)-len(matchedDomain)-1]
	id, err = agd.NewDeviceID(idStr)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", err
	}

	return id, nil
}

// matchDomain searches among domains for one the subdomain of which is sub.  If
// there is no such domain, matchDomain returns an empty string.
func matchDomain(sub string, domains []string) (matchedDomain string) {
	for _, domain := range domains {
		if netutil.IsImmediateSubdomain(sub, domain) {
			return domain
		}
	}

	return ""
}

// DnsmasqCPEIDOption is the identifier of dnsmasq EDNS0 option
// EDNS0_OPTION_NOMCPEID.
//
// See https://github.com/PowerDNS/dnsmasq/blob/master/src/dns-protocol.h.
const DnsmasqCPEIDOption uint16 = 65074

// deviceIDFromEDNS extracts the device ID from EDNS0 option of plain DNS
// request.  This method works with dnsmasq option `--add-cpe-id`, which adds
// an identifying string to DNS queries through [dnsmasqCPEIDOption] option as
// a non-standard support of Nominum servers.  Requests of this kind could also
// be emulated with `+ednsopt` option of `dig` utility:
//
//	dig @94.140.14.49 'edns-id.example' IN A\
//		+ednsopt=65074:"$( printf 'abcd1234' | od -A n -t x1 | tr -d ' ' )"
//
// Any returned errors will have the underlying type of [*deviceIDError].
func deviceIDFromEDNS(req *dns.Msg) (id agd.DeviceID, err error) {
	option := req.IsEdns0()
	if option == nil {
		return "", nil
	}

	for _, opt := range option.Option {
		id, err = deviceIDFromENDSOPT(opt)
		if id != "" || err != nil {
			return id, err
		}
	}

	return "", nil
}

// deviceIDFromENDSOPT inspects opt and, if it's an option that can carry a
// device ID, returns a validated device ID or the validation error.  Any
// returned errors will have the underlying type of [*deviceIDError].
func deviceIDFromENDSOPT(opt dns.EDNS0) (id agd.DeviceID, err error) {
	if opt.Option() != DnsmasqCPEIDOption {
		return "", nil
	}

	o, ok := opt.(*dns.EDNS0_LOCAL)
	if !ok {
		return "", nil
	}

	id, err = agd.NewDeviceID(string(o.Data))
	if err != nil {
		return "", newDeviceIDError(err, "edns option")
	}

	return id, nil
}
