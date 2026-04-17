package dnspb

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// deviceChangesToInternal converts the device changes from protobuf to AdGuard
// DNS devices and deleted IDs.  bindSet, errColl, l, and all elements of
// changes must not be nil.
//
// TODO(a.garipov):  Consider refactoring conversion by using some kind of
// converter struct.
func deviceChangesToInternal(
	ctx context.Context,
	l *slog.Logger,
	changes []*DeviceSettingsChange,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
) (upserted []*agd.Device, ids, deletedIDs []agd.DeviceID, numBad uint) {
	if len(changes) == 0 {
		return nil, nil, nil, 0
	}

	for i, c := range changes {
		d, deletedID, err := deviceChangeToInternal(c.Change, bindSet)
		if d != nil {
			upserted = append(upserted, d)
			ids = append(ids, d.ID)

			continue
		} else if deletedID != "" {
			deletedIDs = append(deletedIDs, deletedID)

			continue
		}

		err = fmt.Errorf("device_changes: at index %d: %w", i, err)
		errcoll.Collect(ctx, errColl, l, "converting device changes", err)

		numBad++
	}

	return upserted, ids, deletedIDs, numBad
}

// deviceChangeToInternal converts a device change to the data about the change.
// All arguments must not be nil.  Only one of d, deleted, and err may not be
// empty.
func deviceChangeToInternal(
	c isDeviceSettingsChange_Change,
	bindSet netutil.SubnetSet,
) (d *agd.Device, deleted agd.DeviceID, err error) {
	switch c := c.(type) {
	case *DeviceSettingsChange_Deleted_:
		deleted, err = agd.NewDeviceID(c.Deleted.DeviceId)
		if err != nil {
			return nil, "", fmt.Errorf("deleted device: %w", err)
		}

		return nil, deleted, nil
	case *DeviceSettingsChange_Upserted_:
		pbd := c.Upserted.Device
		d, err = pbd.ToInternal(bindSet)
		if err != nil {
			return nil, "", fmt.Errorf("upserted device with id %q: %w", pbd.Id, err)
		}

		return d, "", nil
	default:
		return nil, "", fmt.Errorf("device change: %w: %T(%[2]v)", errors.ErrBadEnumValue, c)
	}
}
