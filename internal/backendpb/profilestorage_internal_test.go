package backendpb

import (
	"strconv"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/metadata"
)

func TestSyncTimeFromTrailer(t *testing.T) {
	t.Parallel()

	milliseconds := strconv.FormatInt(TestSyncTime.UnixMilli(), 10)

	testCases := []struct {
		in        metadata.MD
		wantError string
		want      time.Time
		name      string
	}{{
		in:        metadata.MD{},
		wantError: "empty value",
		want:      time.Time{},
		name:      "no_key",
	}, {
		in:        metadata.MD{"sync_time": []string{}},
		wantError: "empty value",
		want:      time.Time{},
		name:      "empty_key",
	}, {
		in:        metadata.MD{"sync_time": []string{""}},
		wantError: `bad value: strconv.ParseInt: parsing "": invalid syntax`,
		want:      time.Time{},
		name:      "empty_value",
	}, {
		in:        metadata.MD{"sync_time": []string{milliseconds}},
		wantError: "",
		want:      TestSyncTime,
		name:      "success",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			syncTime, err := syncTimeFromTrailer(tc.in)
			testutil.AssertErrorMsg(t, tc.wantError, err)
			assert.True(t, tc.want.Equal(syncTime), "want %s; got %s", tc.want, syncTime)
		})
	}
}
