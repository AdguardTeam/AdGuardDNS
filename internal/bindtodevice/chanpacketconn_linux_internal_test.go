//go:build linux

package bindtodevice

import (
	"net"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestChanPacketConn_Close(t *testing.T) {
	sessions := make(chan *packetSession)
	c := newChanPacketConn(sessions, nil, testLAddr)
	err := c.Close()
	assert.NoError(t, err)

	err = c.Close()
	assert.Error(t, err)
}

func TestChanPacketConn_LocalAddr(t *testing.T) {
	c := newChanPacketConn(nil, nil, testLAddr)
	got := c.LocalAddr()
	assert.Equal(t, testLAddr, got)
}

func TestChanPacketConn_ReadFromSession(t *testing.T) {
	sessions := make(chan *packetSession, 1)
	c := newChanPacketConn(sessions, nil, testLAddr)

	body := []byte("hello")
	bodyLen := len(body)

	respOOB := []byte("not a real response oob")

	ps := &packetSession{
		laddr:    testLAddr,
		raddr:    testRAddr,
		readBody: body,
		respOOB:  respOOB,
	}

	sessions <- ps

	deadline := time.Now().Add(testTimeout)
	err := c.SetReadDeadline(deadline)
	require.NoError(t, err)

	b := make([]byte, bodyLen)
	n, sess, err := c.ReadFromSession(b)
	require.NoError(t, err)

	assert.Equal(t, bodyLen, n)
	assert.Equal(t, body, b)

	require.NotNil(t, sess)

	s := testutil.RequireTypeAssert[*packetSession](t, sess)
	assert.Equal(t, respOOB, s.respOOB)

	sessions <- ps

	b = make([]byte, bodyLen)
	n, raddr, err := c.ReadFrom(b)
	require.NoError(t, err)

	assert.Equal(t, bodyLen, n)
	assert.Equal(t, body, b)

	require.NotNil(t, raddr)

	assert.Equal(t, testRAddr, raddr)
}

func TestChanPacketConn_WriteToSession(t *testing.T) {
	sessions := make(chan *packetSession, 1)
	writes := make(chan *packetConnWriteReq, 1)
	c := newChanPacketConn(sessions, writes, testLAddr)

	body := []byte("hello")
	bodyLen := len(body)

	respOOB := []byte("not a real response oob")

	ps := &packetSession{
		laddr:    testLAddr,
		raddr:    testRAddr,
		readBody: nil,
		respOOB:  respOOB,
	}

	deadline := time.Now().Add(testTimeout)
	err := c.SetWriteDeadline(deadline)
	require.NoError(t, err)

	go checkWriteReqAndRespond(writes, nil, body, respOOB, deadline)

	n, err := c.WriteToSession(body, ps)
	require.NoError(t, err)

	assert.Equal(t, bodyLen, n)

	go checkWriteReqAndRespond(writes, testRAddr, body, nil, deadline)

	n, err = c.WriteTo(body, testRAddr)
	require.NoError(t, err)

	assert.Equal(t, bodyLen, n)
}

// checkWriteReqAndRespond is a test helper that receives data from writes,
// checks it against the required values, and sends back a response.
func checkWriteReqAndRespond(
	writes chan *packetConnWriteReq,
	wantRaddr *net.UDPAddr,
	wantBody []byte,
	wantRespOOB []byte,
	wantDeadline time.Time,
) {
	pt := testutil.PanicT{}

	req, ok := testutil.RequireReceive(pt, writes, testTimeout)
	require.NotNil(pt, req)
	require.NotNil(pt, req.resp)
	require.True(pt, ok)

	if wantRaddr != nil {
		assert.Nil(pt, req.session)
		assert.Equal(pt, testRAddr, req.raddr)
	} else {
		require.NotNil(pt, req.session)

		assert.Equal(pt, wantRespOOB, req.session.respOOB)
		assert.Nil(pt, req.raddr)
	}

	assert.Equal(pt, wantDeadline, req.deadline)
	assert.Equal(pt, wantBody, req.body)

	testutil.RequireSend(pt, req.resp, &packetConnWriteResp{
		err:     nil,
		written: len(wantBody),
	}, testTimeout)
}

func TestChanPacketConn_deadlines(t *testing.T) {
	c := newChanPacketConn(nil, nil, testLAddr)
	deadline := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	testCases := []struct {
		f                 func(deadline time.Time) (err error)
		deadline          time.Time
		wantReadDeadline  time.Time
		wantWriteDeadline time.Time
		name              string
	}{{
		f:                 c.SetReadDeadline,
		deadline:          deadline,
		wantReadDeadline:  deadline,
		wantWriteDeadline: time.Time{},
		name:              "read",
	}, {
		f:                 c.SetWriteDeadline,
		deadline:          deadline,
		wantReadDeadline:  time.Time{},
		wantWriteDeadline: deadline,
		name:              "write",
	}, {
		f:                 c.SetDeadline,
		deadline:          deadline,
		wantReadDeadline:  deadline,
		wantWriteDeadline: deadline,
		name:              "both",
	}}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.SetDeadline(time.Time{})
			require.NoError(t, err)

			err = tc.f(tc.deadline)
			require.NoError(t, err)

			assert.Equal(t, tc.wantReadDeadline, c.readDeadline)
			assert.Equal(t, tc.wantWriteDeadline, c.writeDeadline)
		})
	}
}
