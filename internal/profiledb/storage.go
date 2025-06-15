package profiledb

import (
	"context"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
)

// Storage is a storage from which an [Default] receives data about profiles and
// devices.  All methods must be safe for concurrent use.
//
// TODO(a.garipov):  Consider separating into a new package along with its
// errors.
type Storage interface {
	// CreateAutoDevice creates an auto device based on the given data.
	// req must not be nil.
	CreateAutoDevice(
		ctx context.Context,
		req *StorageCreateAutoDeviceRequest,
	) (resp *StorageCreateAutoDeviceResponse, err error)

	// Profiles returns profile and device data that has changed since
	// req.SyncTime.  req must not be nil.
	Profiles(
		ctx context.Context,
		req *StorageProfilesRequest,
	) (resp *StorageProfilesResponse, err error)
}

// StorageCreateAutoDeviceRequest contains the data for a call to the
// [Storage.CreateAutoDevice] method.  All fields should be valid.
type StorageCreateAutoDeviceRequest struct {
	ProfileID  agd.ProfileID
	HumanID    agd.HumanID
	DeviceType agd.DeviceType
}

// StorageCreateAutoDeviceResponse is the response from the
// [Storage.CreateAutoDevice] method.
type StorageCreateAutoDeviceResponse struct {
	// Device is the resulting device.  If the error returned with this response
	// is nil, Device is never nil.
	Device *agd.Device
}

// StorageProfilesRequest contains the data for a call to the [Storage.Profiles]
// method.
type StorageProfilesRequest struct {
	// SyncTime is the last time profiles were synced.
	SyncTime time.Time
}

// StorageProfilesResponse is the response from the [Storage.Profiles] method.
type StorageProfilesResponse struct {
	// SyncTime is the time that should be saved and used as the next
	// [ProfilesRequest.SyncTime].
	SyncTime time.Time

	// DeviceChanges defines the device changes committed in this response.
	//
	// TODO(a.garipov):  This is currently rather badly designed.  Find ways of
	// making this less awkward.
	DeviceChanges map[agd.ProfileID]*StorageDeviceChange

	// Profiles are the profiles data from the [Storage].
	Profiles []*agd.Profile

	// Devices are the device data from the [Storage].
	Devices []*agd.Device
}

// StorageDeviceChange describes changes in the devices of a profile.
type StorageDeviceChange struct {
	// DeletedDeviceIDs are the IDs of devices deleted during a partial update
	// of a profile.
	DeletedDeviceIDs []agd.DeviceID

	// IsPartial is true when the profile has been updated partially.
	IsPartial bool
}
