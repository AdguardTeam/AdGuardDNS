package backendpb

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/netutil"
)

// deviceChangesToInternal is a helper that converts the device changes from
// protobuf to AdGuard DNS devices and deleted IDs.
//
// TODO(a.garipov):  Refactor into a method of [*ProfileStorage].
func deviceChangesToInternal(
	ctx context.Context,
	changes []*DeviceSettingsChange,
	bindSet netutil.SubnetSet,
	errColl errcoll.Interface,
	logger *slog.Logger,
	mtrc ProfileDBMetrics,
) (upserted []*agd.Device, ids, deletedIDs []agd.DeviceID) {
	if len(changes) == 0 {
		return nil, nil, nil
	}

	for i, c := range changes {
		dev, deletedID, err := deviceChangeToInternal(c.Change, bindSet)
		if dev != nil {
			upserted = append(upserted, dev)
			ids = append(ids, dev.ID)

			continue
		} else if deletedID != "" {
			deletedIDs = append(deletedIDs, deletedID)

			continue
		}

		err = fmt.Errorf("device_changes: at index %d: %w", i, err)
		errcoll.Collect(ctx, errColl, logger, "converting device changes", err)

		// TODO(s.chzhen):  Add a return result structure and move the
		// metrics collection to the layer above.
		mtrc.IncrementInvalidDevicesCount(ctx)
	}

	return upserted, ids, deletedIDs
}

// deviceChangeToInternal converts a device change to the data about the change.
// Only one of dev, deleted, and err may not be empty.
func deviceChangeToInternal(
	c isDeviceSettingsChange_Change,
	bindSet netutil.SubnetSet,
) (dev *agd.Device, deleted agd.DeviceID, err error) {
	switch c := c.(type) {
	case *DeviceSettingsChange_Deleted_:
		deleted, err = agd.NewDeviceID(c.Deleted.DeviceId)
		if err != nil {
			return nil, "", fmt.Errorf("deleted device: %w", err)
		}

		return nil, deleted, nil
	case *DeviceSettingsChange_Upserted_:
		d := c.Upserted.Device
		dev, err = d.toInternal(bindSet)
		if err != nil {
			return nil, "", fmt.Errorf("upserted device with id %q: %w", d.Id, err)
		}

		return dev, "", nil
	default:
		return nil, "", fmt.Errorf("device change: %w: %T(%[2]v)", errors.ErrBadEnumValue, c)
	}
}
