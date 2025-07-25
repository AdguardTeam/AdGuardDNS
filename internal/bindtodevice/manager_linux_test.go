//go:build linux

package bindtodevice_test

import (
	"cmp"
	"net"
	"net/netip"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
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

// newTestManager is a helper for creating a [bindtodevice.Manager] for tests.
// c may be nil, and all zero-value fields in c are replaced with test defaults.
func newTestManager(tb testing.TB, c *bindtodevice.ManagerConfig) (m *bindtodevice.Manager) {
	tb.Helper()

	c = cmp.Or(c, &bindtodevice.ManagerConfig{})

	c.Logger = cmp.Or(c.Logger, slogutil.NewDiscardLogger())

	c.InterfaceStorage = cmp.Or[bindtodevice.InterfaceStorage](
		c.InterfaceStorage,
		&fakeInterfaceStorage{
			OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
				return nil, nil
			},
		},
	)

	c.ErrColl = cmp.Or[errcoll.Interface](c.ErrColl, agdtest.NewErrorCollector())
	c.Metrics = cmp.Or[bindtodevice.Metrics](c.Metrics, bindtodevice.EmptyMetrics{})
	c.ChannelBufferSize = cmp.Or(c.ChannelBufferSize, 1)

	m = bindtodevice.NewManager(c)
	require.NotNil(tb, m)

	return m
}

func TestManager_Add(t *testing.T) {
	m := newTestManager(t, nil)

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
	subnet := testSubnetIPv4
	ifaceWithSubnet := &fakeInterface{
		OnSubnets: func() (subnets []netip.Prefix, err error) {
			return []netip.Prefix{subnet}, nil
		},
	}

	m := newTestManager(t, &bindtodevice.ManagerConfig{
		InterfaceStorage: &fakeInterfaceStorage{
			OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
				return ifaceWithSubnet, nil
			},
		},
	})

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

		noSubnetMgr := newTestManager(t, &bindtodevice.ManagerConfig{
			InterfaceStorage: &fakeInterfaceStorage{
				OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
					return ifaceWithoutSubnet, nil
				},
			},
		})

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

		narrowSubnetMgr := newTestManager(t, &bindtodevice.ManagerConfig{
			InterfaceStorage: &fakeInterfaceStorage{
				OnInterfaceByName: func(_ string) (iface bindtodevice.NetInterface, err error) {
					return ifaceWithNarrowerSubnet, nil
				},
			},
		})

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

	m := newTestManager(t, nil)

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

	servicetest.RequireRun(t, m, testTimeout)

	t.Run("tcp", func(t *testing.T) {
		bindtodevice.SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("udp", func(t *testing.T) {
		bindtodevice.SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
	})
}
