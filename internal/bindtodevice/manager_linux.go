//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdnet"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/mapsutil"
	"github.com/AdguardTeam/golibs/syncutil"
	"github.com/miekg/dns"
)

// Manager creates individual listeners and dispatches connections to them.
type Manager struct {
	interfaces     InterfaceStorage
	closeOnce      *sync.Once
	ifaceListeners map[ID]*interfaceListener
	errColl        errcoll.Interface
	done           chan unit
	chanBufSize    int
}

// NewManager returns a new manager of interface listeners.
func NewManager(c *ManagerConfig) (m *Manager) {
	return &Manager{
		interfaces:     c.InterfaceStorage,
		closeOnce:      &sync.Once{},
		ifaceListeners: map[ID]*interfaceListener{},
		errColl:        c.ErrColl,
		done:           make(chan unit),
		chanBufSize:    c.ChannelBufferSize,
	}
}

// defaultCtrlConf is the default control config.  By default, don't alter
// anything.  defaultCtrlConf must not be mutated.
var defaultCtrlConf = &ControlConfig{
	RcvBufSize: 0,
	SndBufSize: 0,
}

// Add creates a new interface-listener record in m.  If conf is nil, a default
// configuration is used.
//
// Add must not be called after Start is called.
func (m *Manager) Add(id ID, ifaceName string, port uint16, ctrlConf *ControlConfig) (err error) {
	defer func() { err = errors.Annotate(err, "adding interface listener with id %q: %w", id) }()

	_, err = m.interfaces.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("looking up interface %q: %w", ifaceName, err)
	}

	validateDup := func(lsnrID ID, lsnr *interfaceListener) (lsnrErr error) {
		lsnrIfaceName, lsnrPort := lsnr.ifaceName, lsnr.port
		if lsnrID == id {
			return fmt.Errorf(
				"listener for interface with id %q already exists: %s:%d",
				lsnrID,
				lsnrIfaceName,
				lsnrPort,
			)
		}

		if lsnrIfaceName == ifaceName && lsnrPort == port {
			return fmt.Errorf(
				"listener for %s:%d already exists with id %q",
				lsnrIfaceName,
				lsnrPort,
				lsnrID,
			)
		}

		return nil
	}

	err = mapsutil.OrderedRangeError(m.ifaceListeners, validateDup)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	if ctrlConf == nil {
		ctrlConf = defaultCtrlConf
	}

	// TODO(a.garipov): Consider customization of body sizes.
	m.ifaceListeners[id] = m.newInterfaceListener(ctrlConf, ifaceName, dns.DefaultMsgSize, port)

	return nil
}

// newInterfaceListener returns a new properly initialized *interfaceListener
// for this manager.
func (m *Manager) newInterfaceListener(
	ctrlConf *ControlConfig,
	ifaceName string,
	bodySize int,
	port uint16,
) (l *interfaceListener) {
	return &interfaceListener{
		conns:         &connIndex{},
		listenConf:    newListenConfig(ifaceName, ctrlConf),
		bodyPool:      syncutil.NewSlicePool[byte](bodySize),
		oobPool:       syncutil.NewSlicePool[byte](netext.IPDstOOBSize),
		writeRequests: make(chan *packetConnWriteReq, m.chanBufSize),
		done:          m.done,
		errColl:       m.errColl,
		ifaceName:     ifaceName,
		port:          port,
	}
}

// ListenConfig returns a new *ListenConfig that receives connections from the
// interface listener with the given id and the destination addresses of which
// fall within subnet.  subnet should be masked.
//
// ListenConfig must not be called after Start is called.
func (m *Manager) ListenConfig(id ID, subnet netip.Prefix) (c *ListenConfig, err error) {
	defer func() {
		err = errors.Annotate(
			err,
			"creating listen config for subnet %s and listener with id %q: %w",
			subnet,
			id,
		)
	}()
	l, ok := m.ifaceListeners[id]
	if !ok {
		return nil, errors.Error("no interface listener found")
	}

	err = m.validateIfaceSubnet(l.ifaceName, subnet)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return nil, err
	}

	lsnrCh := make(chan net.Conn, m.chanBufSize)
	lsnr := newChanListener(lsnrCh, subnet, &agdnet.PrefixNetAddr{
		Prefix: subnet,
		Net:    "tcp",
		Port:   l.port,
	})

	err = l.conns.addListener(lsnr)
	if err != nil {
		return nil, fmt.Errorf("adding tcp conn: %w", err)
	}

	sessCh := make(chan *packetSession, m.chanBufSize)
	pConn := newChanPacketConn(sessCh, subnet, l.writeRequests, &agdnet.PrefixNetAddr{
		Prefix: subnet,
		Net:    "udp",
		Port:   l.port,
	})

	err = l.conns.addPacketConn(pConn)
	if err != nil {
		// Technically shouldn't happen, since [chanIndex.addListenerChannel]
		// has already checked for duplicates.
		return nil, fmt.Errorf("adding udp conn: %w", err)
	}

	return &ListenConfig{
		packetConn: pConn,
		listener:   lsnr,
		addr: &agdnet.PrefixNetAddr{
			Prefix: subnet,
			Net:    "",
			Port:   l.port,
		},
	}, nil
}

// validateIfaceSubnet validates the interface with the name ifaceName exists
// and that it can accept addresses from subnet.
func (m *Manager) validateIfaceSubnet(ifaceName string, subnet netip.Prefix) (err error) {
	if masked := subnet.Masked(); subnet != masked {
		return fmt.Errorf("subnet not masked (expected %s)", masked)
	}

	iface, err := m.interfaces.InterfaceByName(ifaceName)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	ifaceSubnets, err := iface.Subnets()
	if err != nil {
		return fmt.Errorf("getting subnets: %w", err)
	}

	for _, s := range ifaceSubnets {
		if s.Contains(subnet.Addr()) && s.Bits() <= subnet.Bits() {
			return nil
		}
	}

	return fmt.Errorf("interface %s does not contain subnet %s", ifaceName, subnet)
}

// type check
var _ agdservice.Interface = (*Manager)(nil)

// Start implements the [agdservice.Interface] interface for *Manager.  If m is
// nil, Start returns nil, since this feature is optional.
//
// TODO(a.garipov): Consider an interface solution.
//
// TODO(a.garipov): Use the context for cancelation.
func (m *Manager) Start(_ context.Context) (err error) {
	if m == nil {
		return nil
	}

	numListen := 2 * len(m.ifaceListeners)
	errCh := make(chan error, numListen)

	log.Info("bindtodevice: starting %d listeners", numListen)

	for _, lsnr := range m.ifaceListeners {
		go lsnr.listenTCP(errCh)
		go lsnr.listenUDP(errCh)
	}

	errs := make([]error, numListen)
	for i := range errs {
		errs[i] = <-errCh
	}

	err = errors.Join(errs...)
	if err != nil {
		return fmt.Errorf("starting bindtodevice manager: %w", err)
	}

	log.Info("bindtodevice: started all %d listeners", numListen)

	return nil
}

// Shutdown implements the [agdservice.Interface] interface for *Manager.  If m
// is nil, Shutdown returns nil, since this feature is optional.
//
// TODO(a.garipov): Consider an interface solution.
//
// TODO(a.garipov): Consider waiting for all sockets to close.
func (m *Manager) Shutdown(_ context.Context) (err error) {
	if m == nil {
		return nil
	}

	closedNow := false
	m.closeOnce.Do(func() {
		close(m.done)
		closedNow = true
	})

	if !closedNow {
		return net.ErrClosed
	}

	return nil
}
