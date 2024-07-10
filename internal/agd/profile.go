package agd

import (
	"fmt"
	"math"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtime"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/golibs/errors"
)

// Profile contains information about an AdGuard DNS profile.  In other parts of
// the infrastructure, a profile is also called a “DNS server”.  We call it
// profile, because it's less confusing.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
//
// TODO(a.garipov): Consider making it closer to the config file and the backend
// response by grouping parental, rule list, and safe browsing settings into
// separate structs.
type Profile struct {
	// Parental are the parental settings for this profile.  They are ignored if
	// FilteringEnabled is set to false.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	Parental *ParentalProtectionSettings

	// SafeBrowsing are the safe browsing settings for this profile.  They are
	// ignored if FilteringEnabled is set to false.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	SafeBrowsing *SafeBrowsingSettings

	// Access is the access manager for this profile.  Access is never nil.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	Access access.Profile

	// BlockingMode defines the way blocked responses are constructed.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	BlockingMode dnsmsg.BlockingMode

	// ID is the unique ID of this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	ID ProfileID

	// UpdateTime shows the last time this profile was updated from the backend.
	// This is NOT the time of update in the backend's database, since the
	// backend doesn't send this information.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	UpdateTime time.Time

	// DeviceIDs are the IDs of devices attached to this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	DeviceIDs []DeviceID

	// RuleListIDs are the IDs of the filtering rule lists enabled for this
	// profile.  They are ignored if FilteringEnabled or RuleListsEnabled are
	// set to false.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	RuleListIDs []FilterListID

	// CustomRules are the custom filtering rules for this profile.  They are
	// ignored if RuleListsEnabled is set to false.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	CustomRules []FilterRuleText

	// FilteredResponseTTL is the time-to-live value used for responses sent to
	// the devices of this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	FilteredResponseTTL time.Duration

	// FilteringEnabled defines whether queries from devices of this profile
	// should be filtered in any way at all.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	FilteringEnabled bool

	// RuleListsEnabled defines whether queries from devices of this profile
	// should be filtered using the filtering rule lists in RuleListIDs.
	// Requires FilteringEnabled to be set to true.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	RuleListsEnabled bool

	// QueryLogEnabled defines whether query logs should be saved for the
	// devices of this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	QueryLogEnabled bool

	// Deleted shows if this profile is deleted.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	Deleted bool

	// BlockPrivateRelay shows if Apple Private Relay queries are blocked for
	// requests from all devices in this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	BlockPrivateRelay bool

	// BlockFirefoxCanary shows if Firefox canary domain is blocked for
	// requests from all devices in this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	BlockFirefoxCanary bool

	// IPLogEnabled shows if client IP addresses are logged.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	IPLogEnabled bool

	// AutoDevicesEnabled shows if the automatic creation of devices using
	// HumanIDs should be enabled for this profile.
	//
	// NOTE: Do not change fields of this structure without incrementing
	// [internal/profiledb/internal.FileCacheVersion].
	AutoDevicesEnabled bool
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
	if err = ValidateInclusion(len(s), MaxProfileIDLen, 0, UnitByte); err != nil {
		return "", fmt.Errorf("bad profile id %q: %w", s, err)
	}

	// For now, allow only the printable, non-whitespace ASCII characters.
	// Technically we only need to exclude carriage return and line feed
	// characters, but let's be more strict just in case.
	if i, r := firstNonIDRune(s, false); i != -1 {
		return "", fmt.Errorf("bad profile id: bad char %q at index %d", r, i)
	}

	return ProfileID(s), nil
}

// DayRange is a range within a single day.  Start and End are minutes from the
// start of day, with 0 being 00:00:00.(0) and 1439, 23:59:59.(9).
//
// Additionally, if both Start and End are set to [math.MaxUint16], the range is
// a special zero-length range.  This is needed, because when both Start and End
// are zero, such DayRange indicates one minute after midnight; as well as to
// reduce the amount of pointers and thus GC time.
//
// TODO(a.garipov):  Refactor.  See AGDNS-1516.
type DayRange struct {
	Start uint16
	End   uint16
}

// MaxDayRangeMinutes is the maximum value for DayRange.Start and DayRange.End
// fields, excluding the zero-length range ones.
const MaxDayRangeMinutes = 24*60 - 1

// ZeroLengthDayRange returns a new zero-length day range.
func ZeroLengthDayRange() (r DayRange) {
	return DayRange{
		Start: math.MaxUint16,
		End:   math.MaxUint16,
	}
}

// IsZeroLength returns true if r is a zero-length range.
func (r DayRange) IsZeroLength() (ok bool) {
	return r.Start == math.MaxUint16 && r.End == math.MaxUint16
}

// Validate returns the day range validation errors, if any.
func (r DayRange) Validate() (err error) {
	defer func() { err = errors.Annotate(err, "bad day range: %w") }()

	switch {
	case r.IsZeroLength():
		return nil
	case r.End < r.Start:
		return fmt.Errorf("end %d less than start %d", r.End, r.Start)
	case r.Start > MaxDayRangeMinutes:
		return fmt.Errorf("start %d greater than %d", r.Start, MaxDayRangeMinutes)
	case r.End > MaxDayRangeMinutes:
		return fmt.Errorf("end %d greater than %d", r.End, MaxDayRangeMinutes)
	default:
		return nil
	}
}

// WeeklySchedule is a schedule for one week.  The index is the same as
// time.Weekday values.  That is, 0 is Sunday, 1 is Monday, etc.  An empty
// DayRange means that there is no schedule for this day.
type WeeklySchedule [7]DayRange

// ParentalProtectionSchedule is the schedule of a client's parental protection.
// All fields must not be nil.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type ParentalProtectionSchedule struct {
	// Week is the parental protection schedule for every day of the week.
	Week *WeeklySchedule

	// TimeZone is the profile's time zone.
	TimeZone *agdtime.Location
}

// Contains returns true if t is within the allowed schedule.
func (s *ParentalProtectionSchedule) Contains(t time.Time) (ok bool) {
	t = t.In(&s.TimeZone.Location)
	r := s.Week[int(t.Weekday())]
	if r.IsZeroLength() {
		return false
	}

	day := time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, &s.TimeZone.Location)
	start := day.Add(time.Duration(r.Start) * time.Minute)
	end := day.Add(time.Duration(r.End+1)*time.Minute - 1*time.Nanosecond)

	return !t.Before(start) && !t.After(end)
}

// ParentalProtectionSettings are the parental protection settings of a profile.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type ParentalProtectionSettings struct {
	Schedule *ParentalProtectionSchedule

	// BlockedServices are the IDs of the services blocked for this profile.
	BlockedServices []BlockedServiceID

	// Enabled tells whether the parental protection should be enabled at all.
	// This must be true in order for all parameters below to work.
	Enabled bool

	// BlockAdult tells if AdGuard DNS should enforce blocking of adult content
	// using the safe browsing filter.
	BlockAdult bool

	// GeneralSafeSearch tells if AdGuard DNS should enforce general safe search
	// in most search engines.
	GeneralSafeSearch bool

	// YoutubeSafeSearch tells if AdGuard DNS should enforce safe search on
	// YouTube.
	YoutubeSafeSearch bool
}

// SafeBrowsingSettings are the safe browsing settings of a profile.
//
// NOTE: Do not change fields of this structure without incrementing
// [internal/profiledb/internal.FileCacheVersion].
type SafeBrowsingSettings struct {
	// Enabled defines whether queries from devices of this profile should be
	// filtered using the safe browsing filter.  This must be true in order for
	// all parameters below to work.
	Enabled bool

	// BlockDangerousDomains shows whether the dangerous domains safe browsing
	// filtering should be enforced.
	BlockDangerousDomains bool

	// BlockNewlyRegisteredDomains shows whether the newly registered domains
	// safe browsing filtering should be enforced.
	BlockNewlyRegisteredDomains bool
}

// BlockedServiceID is the ID of a blocked service.  While these are usually
// human-readable, clients should treat them as opaque strings.
//
// When a request is blocked by the service blocker, this ID is used as the
// text of the blocking rule.
type BlockedServiceID string

// The maximum and minimum lengths of a blocked service ID.
const (
	MaxBlockedServiceIDLen = 64
	MinBlockedServiceIDLen = 1
)

// NewBlockedServiceID converts a simple string into a BlockedServiceID and
// makes sure that it's valid.  This should be preferred to a simple type
// conversion.
func NewBlockedServiceID(s string) (id BlockedServiceID, err error) {
	defer func() { err = errors.Annotate(err, "bad blocked service id %q: %w", s) }()

	err = ValidateInclusion(len(s), MaxBlockedServiceIDLen, MinBlockedServiceIDLen, UnitByte)
	if err != nil {
		return "", err
	}

	// Allow only the printable, non-whitespace ASCII characters.  Technically
	// we only need to exclude carriage return, line feed, and slash characters,
	// but let's be more strict just in case.
	if i, r := firstNonIDRune(s, true); i != -1 {
		return "", fmt.Errorf("bad char %q at index %d", r, i)
	}

	return BlockedServiceID(s), nil
}
