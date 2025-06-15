package devicefinder

import (
	"strings"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/errors"
)

// parseDeviceData returns either the device ID or the extended human-readable
// ID data depending on what it can parse from s.
//
// TODO(a.garipov):  Optimize error handling etc. based on profiles.
func (f *Default) parseDeviceData(s string) (dd deviceData, err error) {
	if isLikelyExtHumanID(s) {
		var extID *deviceDataExtHumanID
		extID, err = f.parseExtHumanID(s)
		if err != nil {
			// Don't wrap the error, because it's informative enough as is.
			return nil, err
		}

		// NOTE:  Do not remove the condition above and return extID and err,
		// because that leads to the nil-pointer-in-non-nil-interface condition.
		return extID, nil
	}

	// TODO(a.garipov):  Remove once the profile database learns how to match
	// IDs in a case-insensitive way.
	s = strings.ToLower(s)
	id, err := agd.NewDeviceID(s)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	return &deviceDataID{
		id: id,
	}, nil
}

// isLikelyExtHumanID returns true if s likely contains extended human-readable
// device-ID information.
func isLikelyExtHumanID(s string) (ok bool) {
	return strings.Count(s, "-") >= 2
}

// parseExtHumanID parses the data about a device that is identified by a device
// type, a profile ID, and a human-readable device ID.
func (f *Default) parseExtHumanID(s string) (extID *deviceDataExtHumanID, err error) {
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

	return &deviceDataExtHumanID{
		humanID:    humanID,
		profileID:  profID,
		deviceType: dt,
	}, nil
}
