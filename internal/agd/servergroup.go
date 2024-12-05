package agd

import (
	"github.com/AdguardTeam/golibs/container"
	"github.com/miekg/dns"
)

// ServerGroup is a group of DNS servers all of which use the same filtering
// settings.
type ServerGroup struct {
	// DDR is the configuration for the server group's Discovery Of Designated
	// Resolvers (DDR) handlers.  DDR must not be nil.
	DDR *DDR

	// DeviceDomains is the list of domain names used to detect device IDs from
	// clients' server names.
	//
	// TODO(s.chzhen):  Consider using a custom type.
	DeviceDomains []string

	// Name is the unique name of the server group.
	Name ServerGroupName

	// FilteringGroup is the ID of the filtering group for this server group.
	FilteringGroup FilteringGroupID

	// Servers are the settings for servers.  Each element must be non-nil.
	Servers []*Server

	// ProfilesEnabled, if true, enables recognition of user devices and
	// profiles for this server group.
	ProfilesEnabled bool
}

// ServerGroupName is the name of a server group.
type ServerGroupName string

// DDR is the configuration for the server group's Discovery Of Designated
// Resolvers (DDR) handlers.
type DDR struct {
	// DeviceTargets is the set of all domain names, subdomains of which should
	// be checked for DDR queries with device IDs.
	DeviceTargets *container.MapSet[string]

	// PublicTargets is the set of all public domain names, DDR queries for
	// which should be processed.
	PublicTargets *container.MapSet[string]

	// DeviceRecordTemplates are used to respond to DDR queries from recognized
	// devices.
	DeviceRecordTemplates []*dns.SVCB

	// PubilcRecordTemplates are used to respond to DDR queries from
	// unrecognized devices.
	PublicRecordTemplates []*dns.SVCB

	// Enabled shows if DDR queries are processed.  If it is false, DDR domain
	// name queries receive an NXDOMAIN response.
	Enabled bool
}
