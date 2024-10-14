package devicefinder

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/AdguardTeam/AdGuardDNS/internal/optslog"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/miekg/dns"
)

// deviceData extracts the device data from the given parameters.  If the device
// data are not found, all results will be empty, as the lookup could also be
// done later by remote and local addresses.
func (f *Default) deviceData(
	ctx context.Context,
	req *dns.Msg,
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if f.srv.Protocol.IsStdEncrypted() {
		return f.deviceDataFromSrvReqInfo(ctx, srvReqInfo)
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
//  2. Secondly, the TLS Server Name is inspected using the device domains
//     configured for the device finder.
//
// Any returned errors will have the underlying type of [*deviceDataError].
func (f *Default) deviceDataFromSrvReqInfo(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if f.srv.Protocol == agd.ProtoDoH {
		id, extID, err = f.deviceDataForDoH(srvReqInfo)
		if id != "" || extID != nil || err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return id, extID, err
		}
	}

	if len(f.deviceDomains) == 0 {
		return "", nil, nil
	}

	id, extID, err = f.deviceDataFromCliSrvName(ctx, srvReqInfo.TLSServerName)
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
func (f *Default) deviceDataForDoH(
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

	id, extID, err = f.deviceDataFromDoHURL(srvReqInfo.URL)
	if err != nil {
		return "", nil, newDeviceDataError(err, "http url path")
	}

	// In case of empty device data, will continue the lookup process.
	return id, extID, nil
}

// deviceDataFromDoHURL extracts the device data from the path of the DoH
// request.
func (f *Default) deviceDataFromDoHURL(
	u *url.URL,
) (id agd.DeviceID, extID *extHumanID, err error) {
	elems, err := pathElements(u.Path)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return "", nil, err
	}

	if len(elems) == 2 {
		// Don't wrap the error, because it's informative enough as is.
		return f.parseDeviceData(elems[1])
	}

	// pathElements guarantees that if there aren't two elements, there's only
	// one, and it is a valid DNS path.
	return "", nil, nil
}

// pathElements splits and validates urlPath.  If err is nil, elems has either one
// or two elements.
func pathElements(urlPath string) (elems []string, err error) {
	defer func() { err = errors.Annotate(err, "bad path %q: %w", urlPath) }()

	elems = strings.Split(path.Clean(urlPath), "/")
	if elems[0] == "" {
		elems = elems[1:]
	}

	l := len(elems)
	if l == 0 || elems[0] == "" {
		return nil, fmt.Errorf("path elems: %w", errors.ErrNoValue)
	} else if l > 2 {
		return nil, fmt.Errorf("%d extra path elems", l-2)
	}

	if !strings.HasSuffix(dnsserver.PathDoH, elems[0]) &&
		!strings.HasSuffix(dnsserver.PathJSON, elems[0]) {
		return nil, errors.Error("not a dns path")
	}

	return elems, nil
}

// deviceDataFromCliSrvName extracts and validates device data.  cliSrvName is
// the server name as sent by the client.
func (f *Default) deviceDataFromCliSrvName(
	ctx context.Context,
	cliSrvName string,
) (id agd.DeviceID, extID *extHumanID, err error) {
	if cliSrvName == "" {
		// No server name in ClientHello, so the request is probably made on the
		// IP address.
		return "", nil, nil
	}

	matchedDomain := matchDomain(cliSrvName, f.deviceDomains)
	if matchedDomain == "" {
		return "", nil, nil
	}

	optslog.Debug2(
		ctx,
		f.logger,
		"matched device id from domain",
		"domain", matchedDomain,
		"domains", f.deviceDomains,
	)

	idStr := cliSrvName[:len(cliSrvName)-len(matchedDomain)-1]

	// Don't wrap the error, because it's informative enough as is.
	return f.parseDeviceData(idStr)
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
// returned errors will have the underlying type of [*deviceDataError].
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
