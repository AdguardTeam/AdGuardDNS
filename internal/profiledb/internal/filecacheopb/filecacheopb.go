// Package filecacheopb contains encoding and decoding logic for opaque file
// cache.
package filecacheopb

import (
	"fmt"
	"log/slog"

	"github.com/AdguardTeam/AdGuardDNS/internal/access"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"github.com/c2h5oh/datasize"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// toInternal converts the protobuf-encoded data into a cache structure.  fc
// baseCustomLogger, and cons must not be nil.
func fileCacheToInternal(
	fc *fcpb.FileCache,
	baseCustomLogger *slog.Logger,
	cons *access.ProfileConstructor,
	respSzEst datasize.ByteSize,
) (c *internal.FileCache, err error) {
	profiles, err := profilesToInternal(fc.GetProfiles(), baseCustomLogger, cons, respSzEst)
	if err != nil {
		return nil, fmt.Errorf("converting profiles: %w", err)
	}

	devices, err := devicesFromProtobuf(fc.GetDevices())
	if err != nil {
		return nil, fmt.Errorf("converting devices: %w", err)
	}

	return &internal.FileCache{
		SyncTime: fc.GetSyncTime().AsTime(),
		Profiles: profiles,
		Devices:  devices,
		Version:  fc.GetVersion(),
	}, nil
}

// fileCacheToProtobuf converts the cache structure into protobuf structure for
// encoding.
func fileCacheToProtobuf(c *internal.FileCache) (cache *fcpb.FileCache) {
	return fcpb.FileCache_builder{
		SyncTime: timestamppb.New(c.SyncTime),
		Profiles: profilesToProtobuf(c.Profiles),
		Devices:  devicesToProtobuf(c.Devices),
		Version:  c.Version,
	}.Build()
}
