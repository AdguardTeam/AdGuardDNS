package errcoll_test

import (
	"context"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/AdGuardDNS/internal/version"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/testutil/sentrytest"
	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSentryErrorCollector(t *testing.T) {
	gotEventCh := make(chan *sentry.Event, 1)
	tr := &sentrytest.Transport{
		OnClose: func() {
			// Do nothing.
		},
		OnConfigure: func(_ sentry.ClientOptions) {
			// Do nothing.
		},
		OnFlush: func(_ time.Duration) (ok bool) {
			return true
		},
		OnSendEvent: func(e *sentry.Event) {
			gotEventCh <- e
		},
	}

	sentryClient, err := sentry.NewClient(sentry.ClientOptions{
		Dsn:       "https://user:password@does.not.exist/test",
		Transport: tr,
		Release:   version.Version(),
	})
	require.NoError(t, err)

	c := errcoll.NewSentryErrorCollector(sentryClient, slogutil.NewDiscardLogger())

	const devID = "dev1234"
	const fltGrpID = "fg1234"
	const profID = "prof1234"

	reqID := agd.NewRequestID()

	ctx := context.Background()
	ctx = agd.ContextWithRequestInfo(ctx, &agd.RequestInfo{
		DeviceResult: &agd.DeviceResultOK{
			Device:  &agd.Device{ID: devID},
			Profile: &agd.Profile{ID: profID},
		},
		FilteringGroup: &agd.FilteringGroup{ID: fltGrpID},
		Messages:       agdtest.NewConstructor(t),
		ID:             reqID,
	})

	origErr := errors.Error("test error")
	err = fmt.Errorf("wrapped: %w", origErr)
	c.Collect(ctx, err)

	gotEvent := <-gotEventCh
	require.NotNil(t, gotEvent)

	// TODO(a.garipov): Use a transport that is closer to the real one and check
	// other fields of gotEvent such as Version.

	gotExceptions := gotEvent.Exception
	require.NotEmpty(t, gotExceptions)

	assert.Equal(t, origErr.Error(), gotExceptions[0].Value)

	gotExc := gotExceptions[len(gotExceptions)-1]
	assert.Equal(t, err.Error(), gotExc.Value)

	gotTags := maps.Clone(gotEvent.Tags)
	delete(gotTags, "git_revision")

	wantTags := map[string]string{
		"device_id":          devID,
		"filtering_group_id": fltGrpID,
		"profile_id":         profID,
		"request_id":         reqID.String(),
	}
	assert.Equal(t, wantTags, gotTags)
}
