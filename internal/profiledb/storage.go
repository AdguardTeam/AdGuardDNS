package profiledb

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Storage is a storage from which an [Default] receives data about profiles and
// devices.
type Storage interface {
	// Profiles returns profile and device data that has changed since
	// req.SyncTime.  req must not be nil.
	Profiles(ctx context.Context, req *StorageRequest) (resp *StorageResponse, err error)
}

// StorageRequest is the request to [Storage] for profiles and devices.
type StorageRequest struct {
	// SyncTime is the last time profiles were synced.
	SyncTime time.Time
}

// StorageResponse is the ProfileStorage.Profiles response.
type StorageResponse struct {
	// SyncTime is the time that should be saved and used as the next
	// [ProfilesRequest.SyncTime].
	SyncTime time.Time

	// Profiles are the profiles data from the [Storage].
	Profiles []*agd.Profile

	// Devices are the device data from the [Storage].
	Devices []*agd.Device
}
