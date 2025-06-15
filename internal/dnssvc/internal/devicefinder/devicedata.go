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
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/validate"
	"github.com/miekg/dns"
)

// deviceData is the sum type of various pieces of data AdGuard DNS can use to
// recognize a client from the DNS message or TLS data.
//
// The implementations are:
//   - [*deviceDataCustomDomain]
//   - [*deviceDataExtHumanID]
//   - [*deviceDataID]
type deviceData interface {
	// isDeviceData is a marker method.
	isDeviceData()
}

// deviceDataExtHumanID is a [deviceData] that can be parsed from an extended
// human-readable device identifier.
//
// TODO(a.garipov):  Optimize its allocation and freeing.
type deviceDataExtHumanID struct {
	// humanID is the human-readable ID part of an extended humanID.  It must
	// not be empty.
	humanID agd.HumanID

	// profileID is the profile ID part of an extended HumanID.  It must not be
	// empty.
	profileID agd.ProfileID

	// deviceType is the device type of an extended HumanID.  It must be a valid
	// device type and must not be [agd.DeviceTypeNone].
	deviceType agd.DeviceType
}

// type check
var _ deviceData = (*deviceDataExtHumanID)(nil)

// isDeviceData implements the [deviceData] interface for *deviceDataExtHumanID.
func (*deviceDataExtHumanID) isDeviceData() {}

// deviceDataID is a [deviceData] that only contains the ID of the device.
//
// TODO(a.garipov):  Optimize its allocation and freeing.
type deviceDataID struct {
	// id is the ID of the device as parsed from the request.  It must not be
	// empty.
	id agd.DeviceID
}

// type check
var _ deviceData = (*deviceDataID)(nil)

// isDeviceData implements the [deviceData] interface for *deviceDataID.
func (*deviceDataID) isDeviceData() {}

// deviceDataCustomDomain is a [deviceData] that can be derived from the domain
// name.
//
// TODO(a.garipov):  Optimize its allocation and freeing.
type deviceDataCustomDomain struct {
	// deviceData is the underlying device data, which must be either a
	// [deviceDataID] or a [deviceDataExtHumanID].  If it's the latter, the
	// profile IDs must match.
	deviceData deviceData

	// domain is the domain or wildcard that has matched the request.  It must
	// not be empty and must be a valid domain name.
	domain string

	// profileID is the ID of the profile owning the custom domain.  It must not
	// be empty.
	profileID agd.ProfileID
}

// type check
var _ deviceData = (*deviceDataCustomDomain)(nil)

// isDeviceData implements the [deviceData] interface for
// *deviceDataCustomDomain.
func (*deviceDataCustomDomain) isDeviceData() {}

// deviceData extracts the device data from the given parameters.  If the device
// data are not found, dd and err will be nil, as the lookup could also be done
// later by remote and local addresses.
func (f *Default) deviceData(
	ctx context.Context,
	req *dns.Msg,
	srvReqInfo *dnsserver.RequestInfo,
) (dd deviceData, err error) {
	if f.srv.Protocol.IsStdEncrypted() {
		return f.deviceDataFromEncrypted(ctx, srvReqInfo)
	}

	id, err := deviceIDFromEDNS(req)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	} else if id == "" {
		return nil, nil
	}

	return &deviceDataID{
		id: id,
	}, nil
}

// deviceDataFromEncrypted extracts device data from the arguments and checks if
// it's consistent with the custom domains.  srvReqInfo must not be nil.
func (f *Default) deviceDataFromEncrypted(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
) (dd deviceData, err error) {
	cliSrvName := srvReqInfo.TLSServerName
	var customDomain string
	var requiredProfileID agd.ProfileID
	if cliSrvName != "" {
		customDomain, requiredProfileID = f.customDomainDB.Match(ctx, cliSrvName)
	}

	dd, err = f.deviceDataFromSrvReqInfo(ctx, srvReqInfo, customDomain)
	if err != nil {
		return nil, fmt.Errorf("extracting device data: %w", err)
	}

	dd, err = f.wrapCustomDomain(ctx, dd, customDomain, requiredProfileID)
	if err != nil {
		return nil, fmt.Errorf("wrapping custom domains: %w", err)
	}

	return dd, nil
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
//
// If customDomain is not empty, it must be a domain name or wildcard matching
// srvReqInfo.TLSServerName.
func (f *Default) deviceDataFromSrvReqInfo(
	ctx context.Context,
	srvReqInfo *dnsserver.RequestInfo,
	customDomain string,
) (dd deviceData, err error) {
	if f.srv.Protocol == agd.ProtoDoH {
		dd, err = f.deviceDataForDoH(srvReqInfo)
		if dd != nil || err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return dd, err
		}

		// Go on and recheck the TLS parameters.
	}

	if len(f.deviceDomains) == 0 && customDomain == "" {
		// Not matched by URL path and there are neither default nor custom
		// domains.
		f.logger.Log(ctx, slogutil.LevelTrace, "no default or custom domains")

		return nil, nil
	} else if customDomain != "" && !strings.HasPrefix(customDomain, "*.") {
		// The custom domain is not a wildcard, so there cannot be device data
		// in the client server name.
		optslog.Debug1(
			ctx,
			f.logger,
			"domain is not wildcard; not checking tls",
			"matched_domain", customDomain,
		)

		return nil, nil
	}

	customDomain = strings.TrimPrefix(customDomain, "*.")

	dd, err = f.deviceDataFromCliSrvName(ctx, srvReqInfo.TLSServerName, customDomain)
	if err != nil {
		return nil, newDeviceDataError(err, "tls server name")
	}

	return dd, nil
}

// deviceDataForDoH extracts the device data from the DoH request information.
// The data are extracted first from the request's userinfo, if any, and then
// from the URL path.  srvReqInfo must not be nil.
//
// Any returned errors will have the underlying type of [*deviceDataError].
func (f *Default) deviceDataForDoH(srvReqInfo *dnsserver.RequestInfo) (dd deviceData, err error) {
	if userinfo := srvReqInfo.Userinfo; userinfo != nil {
		var id agd.DeviceID
		// Don't scan the userinfo for human-readable IDs, since they're not
		// supported there.
		id, err = agd.NewDeviceID(userinfo.Username())
		if err != nil {
			return nil, newDeviceDataError(err, "basic auth")
		}

		return &deviceDataID{
			id: id,
		}, nil
	}

	dd, err = f.deviceDataFromDoHURL(srvReqInfo.URL)
	if err != nil {
		return nil, newDeviceDataError(err, "http url path")
	}

	// In case of empty device data, will continue the lookup process.
	return dd, nil
}

// deviceDataFromDoHURL extracts the device data from the path of the DoH
// request.
func (f *Default) deviceDataFromDoHURL(u *url.URL) (dd deviceData, err error) {
	elems, err := pathElements(u.Path)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	if len(elems) == 2 {
		// Don't wrap the error, because it's informative enough as is.
		return f.parseDeviceData(elems[1])
	}

	// pathElements guarantees that if there aren't two elements, there's only
	// one, and it is a valid DNS path.
	return nil, nil
}

// wrapCustomDomain wraps dd into a [*deviceDataCustomDomain] if necessary.
func (f *Default) wrapCustomDomain(
	ctx context.Context,
	dd deviceData,
	matchedDomain string,
	requiredProfileID agd.ProfileID,
) (wrapped deviceData, err error) {
	if requiredProfileID == "" {
		return dd, nil
	}

	switch dd := dd.(type) {
	case nil:
		return nil, nil
	case *deviceDataExtHumanID:
		err = validate.Equal("profile id in ext id", dd.profileID, requiredProfileID)
		if err != nil {
			const msg = "custom domain profile and ext id mismatch"
			optslog.Debug2(ctx, f.logger, msg, "got", dd.profileID, "want", requiredProfileID)

			return nil, newDeviceDataError(err, "custom domain")
		}

		return &deviceDataCustomDomain{
			domain:     matchedDomain,
			profileID:  requiredProfileID,
			deviceData: dd,
		}, nil
	case *deviceDataID:
		return &deviceDataCustomDomain{
			domain:     matchedDomain,
			profileID:  requiredProfileID,
			deviceData: dd,
		}, nil
	default:
		panic(fmt.Errorf(
			"wrapping custom domain: device data: %w: %T(%[2]v)",
			errors.ErrBadEnumValue,
			dd,
		))
	}
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
// the server name as sent by the client.  If customDomain is not empty, it
// must be a domain name matching cliSrvName and not a wildcard.
func (f *Default) deviceDataFromCliSrvName(
	ctx context.Context,
	cliSrvName string,
	customDomain string,
) (dd deviceData, err error) {
	if cliSrvName == "" {
		// No server name in ClientHello, so the request is probably made on the
		// IP address.
		return nil, nil
	}

	matchedDomain := customDomain
	if matchedDomain == "" {
		matchedDomain = matchDomain(cliSrvName, f.deviceDomains)
	}

	if matchedDomain == "" {
		return nil, nil
	}

	optslog.Debug2(
		ctx,
		f.logger,
		"matched device id from domain",
		"matched_domain", matchedDomain,
		"server_domains", f.deviceDomains,
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
