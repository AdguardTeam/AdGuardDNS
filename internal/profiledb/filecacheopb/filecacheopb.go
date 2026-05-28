// Package filecacheopb contains encoding and decoding logic for opaque file
// cache.
package filecacheopb

import (
	"cmp"
	"context"
	"fmt"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb"
	"github.com/AdguardTeam/AdGuardDNS/internal/profiledb/internal/fcpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fileCacheToInternal converts the protobuf-encoded data into a cache
// structure.  fc must not be nil.
func (s *Storage) fileCacheToInternal(
	ctx context.Context,
	fc *fcpb.FileCache,
) (c *profiledb.FileCache, err error) {
	profiles, err := s.profilesToInternal(ctx, fc.GetProfiles())
	if err != nil {
		return nil, fmt.Errorf("converting profiles: %w", err)
	}

	devices, err := devicesFromProtobuf(fc.GetDevices())
	if err != nil {
		return nil, fmt.Errorf("converting devices: %w", err)
	}

	return &profiledb.FileCache{
		SyncTime: fc.GetSyncTime().AsTime(),
		Profiles: profiles,
		Devices:  devices,
		Version:  fc.GetVersion(),
	}, nil
}

// fileCacheToProtobuf converts the cache structure into protobuf structure for
// encoding.
func fileCacheToProtobuf(c *profiledb.FileCache) (cache *fcpb.FileCache) {
	slices.SortFunc(c.Profiles, func(a, b *agd.Profile) (res int) {
		return cmp.Compare(a.ID, b.ID)
	})

	slices.SortFunc(c.Devices, func(a, b *agd.Device) (res int) {
		return cmp.Compare(a.ID, b.ID)
	})

	return fcpb.FileCache_builder{
		SyncTime: timestamppb.New(c.SyncTime),
		Profiles: profilesToProtobuf(c.Profiles),
		Devices:  devicesToProtobuf(c.Devices),
		Version:  c.Version,
	}.Build()
}
