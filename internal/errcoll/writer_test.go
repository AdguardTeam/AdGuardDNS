package errcoll_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
)

// testTimeout is the common timeout for tests.
const testTimeout = 1 * time.Second

func TestWriterErrorCollector(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	c := errcoll.NewWriterErrorCollector(&errcoll.WriterErrorCollectorConfig{
		Clock:  timeutil.SystemClock{},
		Writer: buf,
	})
	c.Collect(testutil.ContextWithTimeout(t, testTimeout), assert.AnError)

	got := buf.String()
	assert.Regexp(t, ".*: caught error: "+assert.AnError.Error()+".*", got)
}
