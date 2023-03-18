//go:build linux

package bindtodevice

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/agdmaps"
	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/netext"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Manager creates individual listeners and dispatches connections to them.
type Manager struct {
	closeOnce      *sync.Once
	ifaceListeners map[ID]*interfaceListener
	errColl        agd.ErrorCollector
	done           chan unit
	chanBufSize    int
}

// NewManager returns a new manager of interface listeners.
func NewManager(c *ManagerConfig) (m *Manager) {
	return &Manager{
		closeOnce:      &sync.Once{},
		ifaceListeners: map[ID]*interfaceListener{},
		errColl:        c.ErrColl,
		done:           make(chan unit),
		chanBufSize:    c.ChannelBufferSize,
	}
}

// Add creates a new interface-listener record in m.
//
// Add must not be called after Start is called.
func (m *Manager) Add(id ID, ifaceName string, port uint16) (err error) {
	defer func() { err = errors.Annotate(err, "adding interface listener with id %q: %w", id) }()

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

	err = agdmaps.OrderedRangeError(m.ifaceListeners, validateDup)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	m.ifaceListeners[id] = &interfaceListener{
		channels:      &chanIndex{},
		writeRequests: make(chan *packetConnWriteReq, m.chanBufSize),
		done:          m.done,
		listenConf:    newListenConfig(ifaceName),
		errColl:       m.errColl,
		ifaceName:     ifaceName,
		port:          port,
	}

	return nil
}

// ListenConfig returns a new netext.ListenConfig that receives connections from
// the interface listener with the given id and the destination addresses of
// which fall within subnet.  subnet should be masked.
//
// ListenConfig must not be called after Start is called.
func (m *Manager) ListenConfig(id ID, subnet netip.Prefix) (c netext.ListenConfig, err error) {
	if masked := subnet.Masked(); subnet != masked {
		return nil, fmt.Errorf(
			"subnet %s for interface listener %q not masked (expected %s)",
			subnet,
			id,
			masked,
		)
	}

	l, ok := m.ifaceListeners[id]
	if !ok {
		return nil, fmt.Errorf("no listener for interface %q", id)
	}

	connCh := make(chan net.Conn, m.chanBufSize)
	err = l.channels.addListenerChannel(subnet, connCh)
	if err != nil {
		return nil, fmt.Errorf("adding tcp conn channel: %w", err)
	}

	sessCh := make(chan *packetSession, m.chanBufSize)
	err = l.channels.addPacketConnChannel(subnet, sessCh)
	if err != nil {
		// Technically shouldn't happen, since [chanIndex.addListenerChannel]
		// has already checked for duplicates.
		return nil, fmt.Errorf("adding udp conn channel: %w", err)
	}

	return &chanListenConfig{
		packetConn: newChanPacketConn(sessCh, l.writeRequests, &prefixNetAddr{
			prefix:  subnet,
			network: "udp",
			port:    l.port,
		}),
		listener: newChanListener(connCh, &prefixNetAddr{
			prefix:  subnet,
			network: "tcp",
			port:    l.port,
		}),
	}, nil
}

// type check
var _ agd.Service = (*Manager)(nil)

// Start implements the [agd.Service] interface for *Manager.
func (m *Manager) Start() (err error) {
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

// Shutdown implements the [agd.Service] interface for *Manager.
//
// TODO(a.garipov): Consider waiting for all sockets to close.
func (m *Manager) Shutdown(_ context.Context) (err error) {
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
