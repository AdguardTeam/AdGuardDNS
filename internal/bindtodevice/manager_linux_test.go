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

// type check
var _ bindtodevice.InterfaceStorage = (*fakeInterfaceStorage)(nil)

// fakeInterfaceStorage is a fake [bindtodevice.InterfaceStorage] for tests.
type fakeInterfaceStorage struct {
	OnInterfaceByName func(name string) (iface bindtodevice.NetInterface, err error)
}

// InterfaceByName implements the [bindtodevice.InterfaceStorage] interface
// for *fakeInterfaceStorage.
func (s *fakeInterfaceStorage) InterfaceByName(
	name string,
) (iface bindtodevice.NetInterface, err error) {
	return s.OnInterfaceByName(name)
}

// type check
var _ bindtodevice.NetInterface = (*fakeInterface)(nil)

// fakeInterface is a fake [bindtodevice.Interface] for tests.
type fakeInterface struct {
	OnSubnets func() (subnets []netip.Prefix, err error)
}

// Subnets implements the [bindtodevice.Interface] interface for *fakeInterface.
func (iface *fakeInterface) Subnets() (subnets []netip.Prefix, err error) {
	return iface.OnSubnets()
}

func TestManager_Add(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
	}

	m := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		InterfaceStorage: &fakeInterfaceStorage{
			OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
				return nil, nil
			},
		},
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	// Don't use a table, since the results of these subtests depend on each
	// other.
	t.Run("success", func(t *testing.T) {
		err := m.Add(testID1, testIfaceName, testPort1, nil)
		assert.NoError(t, err)
	})

	t.Run("dup_id", func(t *testing.T) {
		err := m.Add(testID1, testIfaceName, testPort1, nil)
		assert.Error(t, err)
	})

	t.Run("dup_iface_port", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort1, nil)
		assert.Error(t, err)
	})

	t.Run("success_other", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort2, nil)
		assert.NoError(t, err)
	})
}

func TestManager_ListenConfig(t *testing.T) {
	errColl := &agdtest.ErrorCollector{
		OnCollect: func(_ context.Context, _ error) { panic("not implemented") },
	}

	subnet := testSubnetIPv4
	ifaceWithSubnet := &fakeInterface{
		OnSubnets: func() (subnets []netip.Prefix, err error) {
			return []netip.Prefix{subnet}, nil
		},
	}

	m := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		InterfaceStorage: &fakeInterfaceStorage{
			OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
				return ifaceWithSubnet, nil
			},
		},
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	err := m.Add(testID1, testIfaceName, testPort1, nil)
	require.NoError(t, err)

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

	t.Run("no_subnet", func(t *testing.T) {
		ifaceWithoutSubnet := &fakeInterface{
			OnSubnets: func() (subnets []netip.Prefix, err error) {
				return nil, nil
			},
		}

		noSubnetMgr := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
			InterfaceStorage: &fakeInterfaceStorage{
				OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
					return ifaceWithoutSubnet, nil
				},
			},
			ErrColl:           errColl,
			ChannelBufferSize: 1,
		})
		require.NotNil(t, noSubnetMgr)

		subTestErr := noSubnetMgr.Add(testID1, testIfaceName, testPort1, nil)
		require.NoError(t, subTestErr)

		lc, subTestErr := noSubnetMgr.ListenConfig(testID1, subnet)
		assert.Nil(t, lc)
		assert.Error(t, subTestErr)
	})

	t.Run("narrower_subnet", func(t *testing.T) {
		ifaceWithNarrowerSubnet := &fakeInterface{
			OnSubnets: func() (subnets []netip.Prefix, err error) {
				narrowerSubnet := netip.PrefixFrom(subnet.Addr(), subnet.Bits()+4)

				return []netip.Prefix{narrowerSubnet}, nil
			},
		}

		narrowSubnetMgr := bindtodevice.NewManager(&bindtodevice.ManagerConfig{
			InterfaceStorage: &fakeInterfaceStorage{
				OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
					return ifaceWithNarrowerSubnet, nil
				},
			},
			ErrColl:           errColl,
			ChannelBufferSize: 1,
		})
		require.NotNil(t, narrowSubnetMgr)

		subTestErr := narrowSubnetMgr.Add(testID1, testIfaceName, testPort1, nil)
		require.NoError(t, subTestErr)

		lc, subTestErr := narrowSubnetMgr.ListenConfig(testID1, subnet)
		assert.Nil(t, lc)
		assert.Error(t, subTestErr)
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
		InterfaceStorage:  bindtodevice.DefaultInterfaceStorage{},
		ErrColl:           errColl,
		ChannelBufferSize: 1,
	})
	require.NotNil(t, m)

	// TODO(a.garipov): Add support for zero port.
	err := m.Add(testID1, ifaceName, testPort1, nil)
	require.NoError(t, err)

	// TODO(a.garipov): Add tests for addresses within ifaceNet but outside of a
	// narrower subnet.
	subnet, err := netutil.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   ifaceNet.IP.Mask(ifaceNet.Mask),
		Mask: ifaceNet.Mask,
	})
	require.NoError(t, err)

	lc, err := m.ListenConfig(testID1, subnet)
	require.NoError(t, err)
	require.NotNil(t, lc)

	err = m.Start(testutil.ContextWithTimeout(t, testTimeout))
	require.NoError(t, err)
	testutil.CleanupAndRequireSuccess(t, func() (err error) {
		return m.Shutdown(testutil.ContextWithTimeout(t, testTimeout))
	})

	t.Run("tcp", func(t *testing.T) {
		bindtodevice.SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("udp", func(t *testing.T) {
		bindtodevice.SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
	})
}
