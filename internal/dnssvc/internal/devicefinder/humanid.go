package devicefinder

import (
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
)

// extHumanID contains the data that can be parsed from an extended
// human-readable device identifier.
//
// TODO(a.garipov):  Optimize its allocation and freeing.
type extHumanID struct {
	HumanID    agd.HumanID
	ProfileID  agd.ProfileID
	DeviceType agd.DeviceType
}

// parseDeviceData returns either the device ID or the extended human-readable
// ID data depending on what it can parse from the given string.
//
// TODO(a.garipov):  Optimize error handling etc. based on profiles.
func (f *Default) parseDeviceData(s string) (id agd.DeviceID, extID *extHumanID, err error) {
	if isLikelyExtHumanID(s) {
		extID, err = f.parseExtHumanID(s)

		// Don't wrap the error, because it's informative enough as is.
		return "", extID, err
	}

	// TODO(a.garipov):  Remove once the profile database learns how to match
	// IDs in a case-insensitive way.
	s = strings.ToLower(s)
	id, err = agd.NewDeviceID(s)

	// Don't wrap the error, because it's informative enough as is.
	return id, nil, err
}

// isLikelyExtHumanID returns true if s likely contains extended human-readable
// device-ID information.
func isLikelyExtHumanID(s string) (ok bool) {
	return strings.Count(s, "-") >= 2
}

// parseExtHumanID parses the data about a device that is identified by a device
// type, a profile ID, and a human-readable device ID.
func (f *Default) parseExtHumanID(s string) (extID *extHumanID, err error) {
	defer func() { err = errors.Annotate(err, "parsing %q: %w", s) }()

	parts := strings.SplitN(s, "-", 3)
	if len(parts) != 3 {
		// Technically shouldn't happen, as this function should only be called
		// when isLikelyExtHumanID(s) is true.
		return nil, errors.Error("not a valid ext human id")
	}

	// TODO(a.garipov):  Use normalization.
	dt, err := agd.DeviceTypeFromDNS(parts[0])
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	// TODO(a.garipov):  Remove once the profile database learns how to match
	// IDs in a case-insensitive way.
	profIDStr := strings.ToLower(parts[1])
	profID, err := agd.NewProfileID(profIDStr)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	humanID, err := f.humanIDParser.ParseNormalized(parts[2])
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &extHumanID{
		HumanID:    humanID,
		ProfileID:  profID,
		DeviceType: dt,
	}, nil
}
