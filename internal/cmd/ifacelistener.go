package cmd

import (
	"fmt"
	"log/slog"
	"maps"
	"slices"

	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// interfaceListenersConfig contains the optional configuration for the network
// interface listeners and their common parameters.
type interfaceListenersConfig struct {
	// List is the ID-to-configuration mapping of network interface listeners.
	List map[bindtodevice.ID]*interfaceListener `yaml:"list"`

	// ChannelBufferSize is the size of the buffers of the channels used to
	// dispatch TCP connections and UDP sessions.
	ChannelBufferSize int `yaml:"channel_buffer_size"`
}

// toInternal converts c to a possibly-nil bindtodevice.Manager.  c must be
// valid.
func (c *interfaceListenersConfig) toInternal(
	logger *slog.Logger,
	errColl errcoll.Interface,
	ctrlConf *bindtodevice.ControlConfig,
) (m *bindtodevice.Manager, err error) {
	if c == nil {
		return nil, nil
	}

	m = bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		Logger:            logger.With(slogutil.KeyPrefix, "bindtodevice"),
		InterfaceStorage:  bindtodevice.DefaultInterfaceStorage{},
		ErrColl:           errColl,
		ChannelBufferSize: c.ChannelBufferSize,
	})

	for _, id := range slices.Sorted(maps.Keys(c.List)) {
		l := c.List[id]
		err = m.Add(id, l.Interface, l.Port, ctrlConf)
		if err != nil {
			return nil, fmt.Errorf("adding listener %q: %w", id, err)
		}
	}

	return m, nil
}

// type check
var _ validator = (*interfaceListenersConfig)(nil)

// validate implements the [validator] interface for *interfaceListenersConfig.
func (c *interfaceListenersConfig) validate() (err error) {
	switch {
	case c == nil:
		// This configuration is optional.
		//
		// TODO(a.garipov): Consider making required or not relying on nil
		// values.
		return nil
	case c.ChannelBufferSize <= 0:
		return newNotPositiveError("channel_buffer_size", c.ChannelBufferSize)
	case len(c.List) == 0:
		return fmt.Errorf("list: %w", errors.ErrEmptyValue)
	default:
		// Go on.
	}

	for _, id := range slices.Sorted(maps.Keys(c.List)) {
		err = c.List[id].validate()
		if err != nil {
			return fmt.Errorf("interface %q: %w", id, err)
		}
	}

	return err
}

// interfaceListener contains configuration for a single network interface
// listener.
type interfaceListener struct {
	// Interface is the name of the network interface in the system.
	Interface string `yaml:"interface"`

	// Port is the port number on which to listen for incoming connections.
	Port uint16 `yaml:"port"`
}

// type check
var _ validator = (*interfaceListener)(nil)

// validate implements the [validator] interface for *interfaceListener.
func (l *interfaceListener) validate() (err error) {
	switch {
	case l == nil:
		return errors.ErrNoValue
	case l.Port == 0:
		return fmt.Errorf("port: %w", errors.ErrEmptyValue)
	case l.Interface == "":
		return fmt.Errorf("interface: %w", errors.ErrEmptyValue)
	default:
		return nil
	}
}
