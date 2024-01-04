//go:build !linux

package bindtodevice

import (
	"context"
	"fmt"
	"net/netip"

	"github.com/AdguardTeam/AdGuardDNS/internal/agdservice"
	"github.com/AdguardTeam/golibs/errors"
)

// Manager creates individual listeners and dispatches connections to them.
//
// It is only supported on Linux.
type Manager struct{}

// NewManager returns a new manager of interface listeners.
//
// It is only supported on Linux.
func NewManager(c *ManagerConfig) (m *Manager) {
	return &Manager{}
}

// Add creates a new interface-listener record in m.
//
// It is only supported on Linux.
func (m *Manager) Add(id ID, ifaceName string, port uint16, cc *ControlConfig) (err error) {
	return fmt.Errorf("bindtodevice: add: %w; only supported on linux", errors.ErrUnsupported)
}

// ListenConfig returns a new *ListenConfig that receives connections from the
// interface listener with the given id and the destination addresses of which
// fall within subnet.  subnet should be masked.
//
// It is only supported on Linux.
func (m *Manager) ListenConfig(id ID, subnet netip.Prefix) (c *ListenConfig, err error) {
	return nil, fmt.Errorf(
		"bindtodevice: listenconfig: %w; only supported on linux",
		errors.ErrUnsupported,
	)
}

// type check
var _ agdservice.Interface = (*Manager)(nil)

// Start implements the [agdservice.Interface] interface for *Manager.  If m is
// nil, Start returns nil, since this feature is optional.
//
// It is only supported on Linux.
func (m *Manager) Start(_ context.Context) (err error) {
	if m == nil {
		return nil
	}

	return fmt.Errorf("bindtodevice: starting: %w; only supported on linux", errors.ErrUnsupported)
}

// Shutdown implements the [agdservice.Interface] interface for *Manager.  If m
// is nil, Shutdown returns nil, since this feature is optional.
//
// It is only supported on Linux.
func (m *Manager) Shutdown(_ context.Context) (err error) {
	if m == nil {
		return nil
	}

	return fmt.Errorf(
		"bindtodevice: shutting down: %w; only supported on linux",
		errors.ErrUnsupported,
	)
}
