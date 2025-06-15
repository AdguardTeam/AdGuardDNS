package backendpb

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdpasswd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestDeviceChangesToInternal(t *testing.T) {
	t.Parallel()

	const (
		deletedIDStr  = "deletid1"
		upsertedIDStr = "upsrtid1"

		deletedID  agd.DeviceID = deletedIDStr
		upsertedID agd.DeviceID = upsertedIDStr
	)

	const devName = "My Upserted Device"

	upsertedDevSett := &DeviceSettings{
		Id:               upsertedIDStr,
		Name:             devName,
		FilteringEnabled: true,
		LinkedIp:         nil,
		DedicatedIps:     nil,
	}

	upsertedDev := &agd.Device{
		Auth: &agd.AuthSettings{
			PasswordHash: agdpasswd.AllowAuthenticator{},
		},
		ID:               upsertedID,
		Name:             devName,
		FilteringEnabled: true,
	}

	var (
		deletedChange = &DeviceSettingsChange_Deleted_{
			&DeviceSettingsChange_Deleted{
				DeviceId: deletedIDStr,
			},
		}
		upsertedChange = &DeviceSettingsChange_Upserted_{
			Upserted: &DeviceSettingsChange_Upserted{
				Device: upsertedDevSett,
			},
		}
	)

	errColl := agdtest.NewErrorCollector()

	testCases := []struct {
		name       string
		in         []*DeviceSettingsChange
		wantDelIDs []agd.DeviceID
		wantDev    []*agd.Device
		wantIDs    []agd.DeviceID
	}{{
		name:       "empty",
		in:         nil,
		wantDelIDs: nil,
		wantDev:    nil,
		wantIDs:    nil,
	}, {
		name: "deleted",
		in: []*DeviceSettingsChange{{
			Change: deletedChange,
		}},
		wantDelIDs: []agd.DeviceID{deletedID},
		wantDev:    nil,
		wantIDs:    nil,
	}, {
		name: "upserted",
		in: []*DeviceSettingsChange{{
			Change: upsertedChange,
		}},
		wantDelIDs: nil,
		wantDev:    []*agd.Device{upsertedDev},
		wantIDs:    []agd.DeviceID{upsertedID},
	}, {
		name: "both",
		in: []*DeviceSettingsChange{{
			Change: deletedChange,
		}, {
			Change: upsertedChange,
		}},
		wantDelIDs: []agd.DeviceID{deletedID},
		wantDev:    []*agd.Device{upsertedDev},
		wantIDs:    []agd.DeviceID{upsertedID},
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := testutil.ContextWithTimeout(t, TestTimeout)
			gotDev, gotIDs, gotDelIDs := deviceChangesToInternal(
				ctx,
				tc.in,
				TestBind,
				errColl,
				TestLogger,
				EmptyProfileDBMetrics{},
			)
			assert.Equal(t, tc.wantDelIDs, gotDelIDs)
			assert.Equal(t, tc.wantDev, gotDev)
			assert.Equal(t, tc.wantIDs, gotIDs)
		})
	}
}
