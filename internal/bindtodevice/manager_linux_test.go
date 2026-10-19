//go:build linux

package bindtodevice_test

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdtest"
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
	"github.com/AdguardTeam/golibs/netutil"
	"github.com/AdguardTeam/golibs/testutil"
	"github.com/AdguardTeam/golibs/testutil/servicetest"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMetrics is a mock [bindtodevice.Metrics] implementation for tests.
type fakeMetrics struct {
	onIncrementUnknownTCPRequests func(ctx context.Context)
	onIncrementUnknownUDPRequests func(ctx context.Context)
	onSetTCPConnsChanSize         func(ctx context.Context, subnet netip.Prefix, n uint)
	onSetUDPSessionsChanSize      func(ctx context.Context, subnet netip.Prefix, n uint)
	onSetUDPWriteRequestsChanSize func(ctx context.Context, id string, n uint)
	onObserveUDPWriteDuration     func(ctx context.Context, id string, dur time.Duration)
}

// type check
var _ bindtodevice.Metrics = (*fakeMetrics)(nil)

// IncrementUnknownTCPRequests implements the [Metrics] interface for
// *fakeMetrics.
func (f *fakeMetrics) IncrementUnknownTCPRequests(ctx context.Context) {
	f.onIncrementUnknownTCPRequests(ctx)
}

// IncrementUnknownUDPRequests implements the [Metrics] interface for
// *fakeMetrics.
func (f *fakeMetrics) IncrementUnknownUDPRequests(ctx context.Context) {
	f.onIncrementUnknownUDPRequests(ctx)
}

// SetTCPConnsChanSize implements the [Metrics] interface for *fakeMetrics.
func (f *fakeMetrics) SetTCPConnsChanSize(ctx context.Context, subnet netip.Prefix, n uint) {
	f.onSetTCPConnsChanSize(ctx, subnet, n)
}

// SetUDPSessionsChanSize implements the [Metrics] interface for *fakeMetrics.
func (f *fakeMetrics) SetUDPSessionsChanSize(ctx context.Context, prefix netip.Prefix, n uint) {
	f.onSetUDPSessionsChanSize(ctx, prefix, n)
}

// SetUDPWriteRequestsChanSize implements the [Metrics] interface for
// *fakeMetrics.
func (f *fakeMetrics) SetUDPWriteRequestsChanSize(ctx context.Context, id string, n uint) {
	f.onSetUDPWriteRequestsChanSize(ctx, id, n)
}

// ObserveUDPWriteDuration implements the [Metrics] interface for *fakeMetrics.
func (f *fakeMetrics) ObserveUDPWriteDuration(ctx context.Context, id string, dur time.Duration) {
	f.onObserveUDPWriteDuration(ctx, id, dur)
}

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

	c.Clock = cmp.Or[timeutil.Clock](c.Clock, timeutil.SystemClock{})
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
		err := m.Add(testID1, testIfaceName, testPort1, nil, nil)
		assert.NoError(t, err)
	})

	t.Run("dup_id", func(t *testing.T) {
		err := m.Add(testID1, testIfaceName, testPort1, nil, nil)
		assert.Error(t, err)
	})

	t.Run("dup_iface_port", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort1, nil, nil)
		assert.Error(t, err)
	})

	t.Run("success_other", func(t *testing.T) {
		err := m.Add(testID2, testIfaceName, testPort2, nil, nil)
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

	err := m.Add(testID1, testIfaceName, testPort1, nil, nil)
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

		lcDup, lcErr := m.ListenConfig(testID1, subnet)
		assert.NotNil(t, lcDup)
		assert.Same(t, lc, lcDup)
		assert.NoError(t, lcErr)
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

		subTestErr := noSubnetMgr.Add(testID1, testIfaceName, testPort1, nil, nil)
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

		subTestErr := narrowSubnetMgr.Add(testID1, testIfaceName, testPort1, nil, nil)
		require.NoError(t, subTestErr)

		lc, subTestErr := narrowSubnetMgr.ListenConfig(testID1, subnet)
		assert.Nil(t, lc)
		assert.Error(t, subTestErr)
	})
}

// TODO(a.garipov):  Improve [Manager.Shutdown] to make this pass with count=2.
func TestManager(t *testing.T) {
	iface, ifaceNet := bindtodevice.InterfaceForTests(t)
	if iface == nil {
		t.Skipf("skipped: please set env var %s", bindtodevice.TestInterfaceEnvVarName)
	}

	ifaceName := iface.Name

	m := newTestManager(t, &bindtodevice.ManagerConfig{
		InterfaceStorage: bindtodevice.DefaultInterfaceStorage{},
	})

	// TODO(a.garipov): Add support for zero port.
	err := m.Add(testID1, ifaceName, testPort1, nil, nil)
	require.NoError(t, err)

	err = m.Add(testID2, ifaceName, testPort2, nil, nil)
	require.NoError(t, err)

	err = m.Add(testID3, ifaceName, testPort3, nil, nil)
	require.NoError(t, err)

	subnet, err := netutil.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   ifaceNet.IP.Mask(ifaceNet.Mask),
		Mask: ifaceNet.Mask,
	})
	require.NoError(t, err)

	lc, err := m.ListenConfig(testID1, subnet)
	require.NoError(t, err)
	require.NotNil(t, lc)

	lcTLS, err := m.ListenConfig(testID2, subnet)
	require.NoError(t, err)
	require.NotNil(t, lcTLS)

	lcHTTPS, err := m.ListenConfig(testID3, subnet)
	require.NoError(t, err)
	require.NotNil(t, lcHTTPS)

	servicetest.RequireRun(t, m, testTimeout)

	t.Run("udp", func(t *testing.T) {
		bindtodevice.SubtestListenControlUDP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("tcp", func(t *testing.T) {
		bindtodevice.SubtestListenControlTCP(t, lc, ifaceName, ifaceNet)
	})

	t.Run("tls", func(t *testing.T) {
		bindtodevice.SubtestListenControlTLS(t, lcTLS, ifaceName, ifaceNet)
	})

	t.Run("https", func(t *testing.T) {
		bindtodevice.SubtestListenControlHTTPS(t, lcHTTPS, ifaceName, ifaceNet)
	})

	t.Run("doh3", func(t *testing.T) {
		bindtodevice.SubtestListenControlDoH3(t, lcHTTPS, ifaceName, ifaceNet)
	})

	t.Run("quic", func(t *testing.T) {
		bindtodevice.SubtestListenControlQUIC(t, lcTLS, ifaceName, ifaceNet)
	})
}

// TODO(a.garipov):  Improve [Manager.Shutdown] to make this pass with count=2.
func TestManager_outsideSubnet(t *testing.T) {
	iface, ifaceNet := bindtodevice.InterfaceForTests(t)
	if iface == nil {
		t.Skipf("skipped: please set env var %s", bindtodevice.TestInterfaceEnvVarName)
	}

	ifaceSubnet, err := netutil.IPNetToPrefixNoMapped(&net.IPNet{
		IP:   ifaceNet.IP.Mask(ifaceNet.Mask),
		Mask: ifaceNet.Mask,
	})
	require.NoError(t, err)

	if ifaceSubnet.IsSingleIP() {
		t.Skipf("interface subnet %s is too narrow", ifaceSubnet)
	}

	outAddr := ifaceSubnet.Addr()
	narrowAddr := outAddr.Next()
	narrowSubnet := netip.PrefixFrom(narrowAddr, narrowAddr.BitLen())
	require.True(t, ifaceSubnet.Contains(narrowAddr))
	require.False(t, narrowSubnet.Contains(outAddr))

	gotUnknownUDPReq := make(chan struct{})

	m := newTestManager(t, &bindtodevice.ManagerConfig{
		InterfaceStorage: bindtodevice.DefaultInterfaceStorage{},
		Metrics: &fakeMetrics{
			onIncrementUnknownUDPRequests: func(_ context.Context) {
				close(gotUnknownUDPReq)
			},
		},
	})

	err = m.Add(testID1, iface.Name, testPort4, nil, nil)
	require.NoError(t, err)

	lc, err := m.ListenConfig(testID1, narrowSubnet)
	require.NoError(t, err)
	require.NotNil(t, lc)

	servicetest.RequireRun(t, m, testTimeout)

	require.True(t, t.Run("udp", func(t *testing.T) {
		testManagerOutsideSubnetUDP(t, lc, outAddr.AsSlice(), gotUnknownUDPReq)
	}))

	require.True(t, t.Run("tcp", func(t *testing.T) {
		testManagerOutsideSubnetTCP(t, lc, outAddr.AsSlice())
	}))
}

// testManagerOutsideSubnetUDP ensures that packet addressed outside of actual
// lc subnet isn't delivered to lc.
func testManagerOutsideSubnetUDP(
	tb testing.TB,
	lc *bindtodevice.ListenConfig,
	ip net.IP,
	gotUnknownUDPReq chan struct{},
) {
	ctx := testutil.ContextWithTimeout(tb, testTimeout)
	packetConn, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:0")
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, packetConn.Close)

	remoteConn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   ip,
		Port: int(lc.Addr().Port),
	})
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, remoteConn.Close)

	_, err = remoteConn.Write([]byte("test"))
	require.NoError(tb, err)

	testutil.RequireReceive(tb, gotUnknownUDPReq, testTimeout)

	err = packetConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(tb, err)

	var netError net.Error
	n, _, err := packetConn.ReadFrom(make([]byte, 4))
	require.ErrorAs(tb, err, &netError)
	require.True(tb, netError.Timeout())

	assert.Zero(tb, n)
}

// testManagerOutsideSubnetTCP ensures that connection addressed outside of
// actual lc subnet is closed instead of being delivered to lc.
func testManagerOutsideSubnetTCP(tb testing.TB, lc *bindtodevice.ListenConfig, ip net.IP) {
	remoteConn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   ip,
		Port: int(lc.Addr().Port),
	})
	require.NoError(tb, err)
	testutil.CleanupAndRequireSuccess(tb, remoteConn.Close)

	err = remoteConn.SetReadDeadline(time.Now().Add(testTimeout))
	require.NoError(tb, err)

	var netError net.Error
	n, err := remoteConn.Read(make([]byte, 1))
	require.ErrorAs(tb, err, &netError)
	require.True(tb, netError.Timeout())

	assert.Zero(tb, n)
}
