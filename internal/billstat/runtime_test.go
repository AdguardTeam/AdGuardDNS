package billstat_test

import (
	"context"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/billstat"
	"github.com/AdguardTeam/AdGuardDNS/internal/geoip"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sig is a convenient alias for struct{} when it's used as a signal for
// synchronization.
type sig = struct{}

// Common constants for tests.
const (
	devID                = "dev1234"
	proto                = agd.ProtoDoH
	clientCtry           = geoip.CountryAD
	clientASN  geoip.ASN = 42
)

func TestRuntimeRecorder_success(t *testing.T) {
	var gotRecord *billstat.Record
	c := &billstat.RuntimeRecorderConfig{
		Uploader: &agdtest.BillStatUploader{
			OnUpload: func(_ context.Context, records billstat.Records) (err error) {
				gotRecord = records[devID]

				return nil
			},
		},
	}

	r := billstat.NewRuntimeRecorder(c)

	ctx := context.Background()
	start := time.Now().Truncate(1 * time.Millisecond)

	// Record two queries to make sure that the queries counter is properly
	// incremented.
	const reqNum = 2
	var err error
	for i := 0; i < reqNum; i++ {
		r.Record(ctx, devID, clientCtry, clientASN, start, proto)
	}

	err = r.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, gotRecord)

	assert.Equal(t, gotRecord.Time, start)
	assert.Equal(t, gotRecord.Country, clientCtry)
	assert.Equal(t, gotRecord.ASN, clientASN)
	assert.Equal(t, gotRecord.Queries, int32(reqNum))
	assert.Equal(t, gotRecord.Proto, proto)
}

func TestRuntimeRecorder_fail(t *testing.T) {
	const testError errors.Error = "test error"
	var emulateFail bool
	var gotRecord *billstat.Record
	uploadSync := make(chan sig)
	onUpload := func(_ context.Context, records billstat.Records) (err error) {
		if emulateFail {
			pt := testutil.PanicT{}

			// Give the goroutine a signal that it can now record another query
			// to emulate a situation where a query gets recorded while an
			// upload is in progress.
			testutil.RequireSend(pt, uploadSync, sig{}, testTimeout)

			// Wait for the other query in the goroutine to be recorded and
			// proceed to returning an error after that.
			testutil.RequireReceive(pt, uploadSync, testTimeout)

			return testError
		}

		gotRecord = records[devID]

		return nil
	}

	c := &billstat.RuntimeRecorderConfig{
		Uploader: &agdtest.BillStatUploader{
			OnUpload: onUpload,
		},
	}

	r := billstat.NewRuntimeRecorder(c)

	ctx := context.Background()
	start := time.Now().Truncate(1 * time.Millisecond)

	r.Record(ctx, devID, clientCtry, clientASN, start, proto)

	// Request the backend, make a concurrent request while an upload is in
	// progress, receive the error, and expect the data to be returned to the
	// database and properly merged.
	emulateFail = true
	go func() {
		pt := testutil.PanicT{}

		testutil.RequireReceive(pt, uploadSync, testTimeout)

		r.Record(ctx, devID, clientCtry, clientASN, start, proto)

		testutil.RequireSend(pt, uploadSync, sig{}, testTimeout)
	}()

	err := r.Refresh(context.Background())
	require.ErrorIs(t, err, testError)
	require.Nil(t, gotRecord)

	// Request the backend again, expect the correct, merged data.
	emulateFail = false
	err = r.Refresh(context.Background())
	require.NoError(t, err)
	require.NotNil(t, gotRecord)

	assert.Equal(t, gotRecord.Time, start)
	assert.Equal(t, gotRecord.Country, clientCtry)
	assert.Equal(t, gotRecord.ASN, clientASN)
	assert.Equal(t, gotRecord.Queries, int32(2))
	assert.Equal(t, gotRecord.Proto, proto)
}
