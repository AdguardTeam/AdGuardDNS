//go:build linux

package bindtodevice_test

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TODO(a.garipov): Add tests for other platforms?

func TestManager_Add(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
	}

	m := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	// Don't use a table, since the results of these subtests depend on each
	// other.
	t.Run("success", func(t *testing.T) {
		err := m.Add(testID1, testIfaceName, testPort1)
		assert.NoError(t, err)
	})

	t.Run("dup_id", func(t *testing.T) {
		err := m.Add(testID1, testIfaceName, testPort1)
		assert.Error(t, err)
	})

	t.Run("dup_iface_port", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort1)
		assert.Error(t, err)
	})

	t.Run("success_other", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort2)
		assert.NoError(t, err)
	})
}

func TestManager_ListenConfig(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
	}

	m := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	err := m.Add(testID1, testIfaceName, testPort1)
	require.NoError(t, err)

	subnet := netip.MustParsePrefix("1.2.3.0/24")

	// Don't use a table, since the results of these subtests depend on each
	// other.
	t.Run("not_found", func(t *testing.T) {
		lc, lcErr := m.ListenConfig(testID2, subnet)
		assert.Nil(t, lc)
		assert.Error(t, lcErr)
	})

	t.Run("unmasked", func(t *testing.T) {
		badSubnet := netip.MustParsePrefix("1.2.3.4/24")
		lc, lcErr := m.ListenConfig(testID1, badSubnet)
		assert.Nil(t, lc)
		assert.Error(t, lcErr)
	})

	t.Run("success", func(t *testing.T) {
		lc, lcErr := m.ListenConfig(testID1, subnet)
		assert.NotNil(t, lc)
		assert.NoError(t, lcErr)
	})

	t.Run("dup", func(t *testing.T) {
		lc, lcErr := m.ListenConfig(testID1, subnet)
		assert.Nil(t, lc)
		assert.Error(t, lcErr)
	})
}

func TestManager(t *testing.T) {
	iface, ifaceNet := bindtodevice.InterfaceForTests(t)
	if iface == nil {
		t.Skipf(
			"test %s skipped: please set env var %s",
			t.Name(),
			bindtodevice.TestInterfaceEnvVarName,
		)
	}

	ifaceName := iface.Name

	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
	}

	m := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	// TODO(a.garipov): Add support for zero port.
	err := m.Add(testID1, ifaceName, testPort1)
	require.NoError(t, err)

	subnet, err := netutil.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   ifaceNet.IP.Mask(ifaceNet.Mask),
		Mask: ifaceNet.Mask,
	})
	require.NoError(t, err)

	lc, err := m.ListenConfig(testID1, subnet)
	require.NoError(t, err)
	require.NotNil(t, lc)

	err = m.Start()
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return m.Shutdown(context.Background())
	})

	t.Run("tcp", func(t *testing.T) {
		bindtodevice.SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("udp", func(t *testing.T) {
		bindtodevice.SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
	})
}
