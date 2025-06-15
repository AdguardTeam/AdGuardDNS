// Package profiledb defines interfaces for databases of user profiles.
package profiledb

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// syncTimeFull is the time used in full sync profile requests.
var syncTimeFull = time.Time{}

// Interface is the local database of user profiles and devices.
//
// NOTE:  All returned values must not be modified.
type Interface interface {
	// CreateAutoDevice creates a new automatic device for the given profile
	// with the given human-readable device ID and device type.  All arguments
	// must be valid.
	CreateAutoDevice(
		ctx context.Context,
		id agd.ProfileID,
		humanID agd.HumanID,
		devType agd.DeviceType,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByDedicatedIP returns the profile and the device identified by its
	// dedicated DNS server IP address.  ip must be valid.
	ProfileByDedicatedIP(
		ctx context.Context,
		ip netip.Addr,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByDeviceID returns the profile and the device identified by id.
	// id must be valid.
	ProfileByDeviceID(
		ctx context.Context,
		id agd.DeviceID,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByHumanID returns the profile and the device identified by the
	// profile ID and the lowercase version of the human-readable device ID.
	// id and humanIDLower must be valid.
	ProfileByHumanID(
		ctx context.Context,
		id agd.ProfileID,
		humanIDLower agd.HumanIDLower,
	) (p *agd.Profile, d *agd.Device, err error)

	// ProfileByLinkedIP returns the profile and the device identified by its
	// linked IP address.  ip must be valid.
	ProfileByLinkedIP(ctx context.Context, ip netip.Addr) (p *agd.Profile, d *agd.Device, err error)
}

// type check
var _ Interface = (*Disabled)(nil)

// Disabled is a profile database that panics on any call.
type Disabled struct{}

// profilesDBUnexpectedCall is a panic message template for lookup methods when
// profiles database is disabled.
const profilesDBUnexpectedCall string = "profiles db: unexpected call to %s"

// CreateAutoDevice implements the [Interface] interface for *Disabled.
func (d *Disabled) CreateAutoDevice(
	_ context.Context,
	_ agd.ProfileID,
	_ agd.HumanID,
	_ agd.DeviceType,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "CreateAutoDevice"))
}

// ProfileByDedicatedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDedicatedIP(
	_ context.Context,
	_ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDedicatedIP"))
}

// ProfileByDeviceID implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByDeviceID(
	_ context.Context,
	_ agd.DeviceID,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByDeviceID"))
}

// ProfileByHumanID implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByHumanID(
	_ context.Context,
	_ agd.ProfileID,
	_ agd.HumanIDLower,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByHumanID"))
}

// ProfileByLinkedIP implements the [Interface] interface for *Disabled.
func (d *Disabled) ProfileByLinkedIP(
	_ context.Context,
	_ netip.Addr,
) (_ *agd.Profile, _ *agd.Device, _ error) {
	panic(fmt.Errorf(profilesDBUnexpectedCall, "ProfileByLinkedIP"))
}
