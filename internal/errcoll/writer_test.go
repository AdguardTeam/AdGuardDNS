package errcoll_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/stretchr/testify/assert"
)

func TestWriterErrorCollector(t *testing.T) {
	buf := &bytes.Buffer{}
	c := errcoll.NewWriterErrorCollector(buf)
	c.Collect(context.Background(), errors.Error("test error"))

	wantRx := `.*: .*errcoll/writer_test.go:[0-9]+: caught error: test error.*`
	got := buf.String()
	assert.Regexp(t, wantRx, got)
}
