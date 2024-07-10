package agd_test

import (
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
)

func TestDeviceTypeFromDNS(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name       string
		in         string
		wantErrMsg string
		want       agd.DeviceType
	}{{
		name:       "success",
		in:         "adr",
		wantErrMsg: "",
		want:       agd.DeviceTypeAndroid,
	}, {
		name:       "success_case",
		in:         "Adr",
		wantErrMsg: "",
		want:       agd.DeviceTypeAndroid,
	}, {
		name:       "too_long",
		in:         "windows",
		wantErrMsg: `bad device type "windows": too long: got 7 bytes, max 3`,
		want:       agd.DeviceTypeNone,
	}, {
		name:       "too_small",
		in:         "x",
		wantErrMsg: `bad device type "x": too short: got 1 bytes, min 3`,
		want:       agd.DeviceTypeNone,
	}, {
		name:       "none",
		in:         "(none)",
		wantErrMsg: `bad device type "(none)": too long: got 6 bytes, max 3`,
		want:       agd.DeviceTypeNone,
	}, {
		name:       "unknown",
		in:         "xxx",
		wantErrMsg: `bad device type "xxx": unknown device type`,
		want:       agd.DeviceTypeNone,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := agd.DeviceTypeFromDNS(tc.in)
			assert.Equal(t, tc.want, got)
			testutil.AssertErrorMsg(t, tc.wantErrMsg, err)
		})
	}
}

func TestDeviceType_String(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "(none)", agd.DeviceTypeNone.String())
	assert.Equal(t, "adr", agd.DeviceTypeAndroid.String())
	assert.Equal(t, "!bad_device_type_42", agd.DeviceType(42).String())
}
