package errcoll_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsmsg"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/getsentry/raven-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRavenTransport is a raven.Transport for tests.
type testRavenTransport struct {
	onSend func(url, authHeader string, packet *raven.Packet) (err error)
}

// Send implements the raven.Transport interface for *testRavenTransport.
func (t *testRavenTransport) Send(url, authHeader string, packet *raven.Packet) (err error) {
	return t.onSend(url, authHeader, packet)
}

func TestRavenErrorCollector(t *testing.T) {
	gotPacketCh := make(chan *raven.Packet, 1)
	rt := &testRavenTransport{
		onSend: func(_, _ string, packet *raven.Packet) (err error) {
			gotPacketCh <- packet

			return nil
		},
	}

	rc, err := raven.New("https://user:password@does.not.exist/test")
	require.NoError(t, err)

	rc.Transport = rt
	c := errcoll.NewRavenErrorCollector(rc)

	const devID = "dev1234"
	const fgID = "fg1234"
	const profID = "prof1234"
	const reqID = "req5678"

	ctx := context.Background()
	ctx = agd.ContextWithRequestInfo(ctx, &agd.RequestInfo{
		Device:         &agd.Device{ID: devID},
		Profile:        &agd.Profile{ID: profID},
		FilteringGroup: &agd.FilteringGroup{ID: fgID},
		Messages: &dnsmsg.Constructor{
			FilteredResponseTTL: 10 * time.Second,
		},
		ID: reqID,
	})

	err = fmt.Errorf("wrapped: %w", errors.Error("test error"))
	c.Collect(ctx, err)

	gotPacket := <-gotPacketCh
	assert.Equal(t, err.Error(), gotPacket.Message)

	type ravenTags = map[string]string
	tags := make(ravenTags, len(gotPacket.Tags))
	for _, tag := range gotPacket.Tags {
		tags[tag.Key] = tag.Value
	}

	position := tags["position"]
	delete(tags, "position")
	delete(tags, "version")
	delete(tags, "git_revision")

	wantRx := `.*errcoll/raven_test.go:[0-9]+.*`
	assert.Regexp(t, wantRx, position)

	wantTags := ravenTags{
		"device_id":          devID,
		"filtering_group_id": fgID,
		"profile_id":         profID,
		"request_id":         reqID,
		"unwrapped_type":     "errors.Error",
	}
	assert.Equal(t, wantTags, tags)
}
