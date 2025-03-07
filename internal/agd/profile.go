package agd

import (
	"fmt"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdvalidate"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
)

// Profile contains information about an AdGuard DNS profile.  In other parts of
// the infrastructure, a profile is also called a “DNS server”.  We call it
// profile, because it's less confusing.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
//
// TODO(a.garipov):  Extract the pre-filtering booleans and logic into a new
// package.
type Profile struct {
	// FilterConfig is the configuration of the filters used for this profile
	// and all its devices that don't have filtering disabled.  It must not be
	// nil.
	FilterConfig *filter.ConfigClient

	// Access is the access manager for this profile.  It must not be nil.
	Access access.Profile

	// BlockingMode defines the way blocked responses are constructed.  It must
	// not be nil.
	BlockingMode dnsmsg.BlockingMode

	// Ratelimiter is the custom ratelimiter for this profile.  It must not be
	// nil.
	Ratelimiter Ratelimiter

	// ID is the unique ID of this profile.  It must not be empty.
	ID ProfileID

	// DeviceIDs are the IDs of devices attached to this profile.
	DeviceIDs []DeviceID

	// FilteredResponseTTL is the time-to-live value used for responses sent to
	// the devices of this profile.
	FilteredResponseTTL time.Duration

	// AutoDevicesEnabled shows if the automatic creation of devices using
	// HumanIDs should be enabled for this profile.
	AutoDevicesEnabled bool

	// BlockChromePrefetch shows if the Chrome prefetch proxy feature should be
	// forced into preflight mode for all devices in this profile.
	BlockChromePrefetch bool

	// BlockFirefoxCanary shows if Firefox canary domain is blocked for
	// requests from all devices in this profile.
	BlockFirefoxCanary bool

	// BlockPrivateRelay shows if Apple Private Relay queries are blocked for
	// requests from all devices in this profile.
	BlockPrivateRelay bool

	// Deleted shows if this profile is deleted.
	Deleted bool

	// FilteringEnabled defines whether queries from devices of this profile
	// should be filtered in any way at all.
	FilteringEnabled bool

	// IPLogEnabled shows if client IP addresses are logged.
	IPLogEnabled bool

	// QueryLogEnabled defines whether query logs should be saved for the
	// devices of this profile.
	QueryLogEnabled bool
}

// ProfileID is the ID of a profile.  It is an opaque string.
//
// In other parts of the infrastructure, it's also known as “DNS ID” and “DNS
// Server ID”.
type ProfileID string

// MaxProfileIDLen is the maximum length of a profile ID.
const MaxProfileIDLen = 8

// NewProfileID converts a simple string into a ProfileID and makes sure that
// it's valid.  This should be preferred to a simple type conversion.
func NewProfileID(s string) (id ProfileID, err error) {
	if err = agdvalidate.Inclusion(len(s), 0, MaxProfileIDLen, agdvalidate.UnitByte); err != nil {
		return "", fmt.Errorf("bad profile id %q: %w", s, err)
	}

	// For now, allow only the printable, non-whitespace ASCII characters.
	// Technically we only need to exclude carriage return and line feed
	// characters, but let's be more strict just in case.
	if i, r := agdvalidate.FirstNonIDRune(s, false); i != -1 {
		return "", fmt.Errorf("bad profile id: bad char %q at index %d", r, i)
	}

	return ProfileID(s), nil
}
