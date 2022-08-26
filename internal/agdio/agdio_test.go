package agdio_test

import (
	"io"
	"strings"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLimitedReader_Read(t *testing.T) {
	testCases := []struct {
		err   error
		name  string
		rStr  string
		limit int64
		want  int
	}{{
		err:   nil,
		name:  "perfectly_match",
		rStr:  "abc",
		limit: 3,
		want:  3,
	}, {
		err:   io.EOF,
		name:  "eof",
		rStr:  "",
		limit: 3,
		want:  0,
	}, {
		err: &agdio.LimitError{
			Limit: 0,
		},
		name:  "limit_reached",
		rStr:  "abc",
		limit: 0,
		want:  0,
	}, {
		err:   nil,
		name:  "truncated",
		rStr:  "abc",
		limit: 2,
		want:  2,
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			readCloser := io.NopCloser(strings.NewReader(tc.rStr))
			buf := make([]byte, tc.limit+1)

			lreader := agdio.LimitReader(readCloser, tc.limit)
			n, err := lreader.Read(buf)
			require.Equal(t, tc.err, err)

			assert.Equal(t, tc.want, n)
		})
	}
}

func TestLimitError_Error(t *testing.T) {
	err := &agdio.LimitError{
		Limit: 0,
	}

	const want = "cannot read more than 0 bytes"
	assert.Equal(t, want, err.Error())
}
