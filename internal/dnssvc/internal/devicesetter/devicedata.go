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

// deviceData extracts the device data from the given parameters.  If the device
// data are not found, all results will be empty, as the lookup could also be
// done later by remote and local addresses.
func (ds *Default) deviceData(
	req *dns.Msg,
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if ds.srv.Protocol.IsStdEncrypted() {
		return ds.deviceDataFromSrvReqInfo(srvReqInfo)
	}

	id, err = deviceIDFromEDNS(req)

	return id, nil, err
}

// deviceDataFromSrvReqInfo extracts device data from the arguments.  The data
// are extracted in the following manner:
//
//  1. If applicable, the data is first extracted from the DoH information, such
//     as the userinfo or URL path.
//
//  2. Secondly, the TLS Server Name is inspected using the device-ID wildcards
//     configured for the device setter.
//
// Any returned errors will have the underlying type of [*deviceIDError].
func (ds *Default) deviceDataFromSrvReqInfo(
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if ds.srv.Protocol == agd.ProtoDoH {
		id, extID, err = ds.deviceDataForDoH(srvReqInfo)
		if id != "" || extID != nil || err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return id, extID, err
		}
	}

	if len(ds.wildcardDomains) == 0 {
		return "", nil, nil
	}

	id, extID, err = ds.deviceDataFromCliSrvName(srvReqInfo.TLSServerName)
	if err != nil {
		return "", nil, newDeviceDataError(err, "tls server name")
	}

	return id, extID, nil
}

// deviceDataForDoH extracts the device data from the DoH request information.
// The data are extracted first from the request's userinfo, if any, and then
// from the URL path.  srvReqInfo must not be nil.
//
// Any returned errors will have the underlying type of [*deviceDataError].
func (ds *Default) deviceDataForDoH(
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if userinfo := srvReqInfo.Userinfo; userinfo != nil {
		// Don't scan the userinfo for human-readable IDs, since they're not
		// supported there.
		id, err = agd.NewDeviceID(userinfo.Username())
		if err != nil {
			return "", nil, newDeviceDataError(err, "basic auth")
		}

		return id, nil, nil
	}

	id, extID, err = ds.deviceDataFromDoHURL(srvReqInfo.URL)
	if err != nil {
		return "", nil, newDeviceDataError(err, "http url path")
	}

	// In case of empty device data, will continue the lookup process.
	return id, extID, nil
}

// deviceDataFromDoHURL extracts the device data from the path of the DoH
// request.
func (ds *Default) deviceDataFromDoHURL(
	u *url.URL,
) (id agd.DeviceID, extID *extHumanID, err error) {
	parts, err := pathParts(u.Path)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", nil, err
	}

	if len(parts) == 2 {
		// Don't wrap the error, because it's informative enough as is.
		return ds.parseDeviceData(parts[1])
	}

	// pathParts guarantees that if there aren't two parts, there's only one,
	// and it is a valid DNS path.
	return "", nil, nil
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

// deviceDataFromCliSrvName extracts and validates device data.  cliSrvName is
// the server name as sent by the client.
func (ds *Default) deviceDataFromCliSrvName(
	cliSrvName string,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if cliSrvName == "" {
		// No server name in ClientHello, so the request is probably made on the
		// IP address.
		return "", nil, nil
	}

	matchedDomain := matchDomain(cliSrvName, ds.wildcardDomains)
	if matchedDomain == "" {
		return "", nil, nil
	}

	optlog.Debug2("devicesetter: device id: matched %q from %q", matchedDomain, ds.wildcardDomains)

	idStr := cliSrvName[:len(cliSrvName)-len(matchedDomain)-1]

	// Don't wrap the error, because it's informative enough as is.
	return ds.parseDeviceData(idStr)
}

// matchDomain searches among domains for one the subdomain of which is sub.  If
// there is no such domain, matchDomain returns an empty string.
func matchDomain(sub string, domains []string) (matchedDomain string) {
	// TODO(a.garipov):  Remove once netutil learns how to match domains in a
	// case-insensitive way.
	sub = strings.ToLower(sub)
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
// Any returned errors will have the underlying type of [*deviceDataError].
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
		return "", newDeviceDataError(err, "edns option")
	}

	return id, nil
}
