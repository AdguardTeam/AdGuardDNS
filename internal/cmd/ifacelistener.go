package cmd

import (
	"github.com/AdguardTeam/AdGuardDNS/internal/bindtodevice"
	"github.com/AdguardTeam/AdGuardDNS/internal/errcoll"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/mapsutil"
)

// Network interface listener configuration

// interfaceListenersConfig contains the optional configuration for the network
// interface listeners and their common parameters.
type interfaceListenersConfig struct {
	// List is the ID-to-configuration mapping of network interface listeners.
	List map[bindtodevice.ID]*interfaceListener `yaml:"list"`

	// ChannelBufferSize is the size of the buffers of the channels used to
	// dispatch TCP connections and UDP sessions.
	ChannelBufferSize int `yaml:"channel_buffer_size"`
}

// toInternal converts c to a bindtodevice.Manager.  c is assumed to be valid.
func (c *interfaceListenersConfig) toInternal(
	errColl errcoll.Interface,
	ctrlConf *bindtodevice.ControlConfig,
) (m *bindtodevice.Manager, err error) {
	if c == nil {
		return nil, nil
	}

	m = bindtodevice.NewManager(&bindtodevice.ManagerConfig{
		InterfaceStorage:  bindtodevice.DefaultInterfaceStorage{},
		ErrColl:           errColl,
		ChannelBufferSize: c.ChannelBufferSize,
	})

	err = mapsutil.SortedRangeError(
		c.List,
		func(id bindtodevice.ID, l *interfaceListener) (addErr error) {
			return errors.Annotate(m.Add(id, l.Interface, l.Port, ctrlConf), "adding listener %q: %w", id)
		},
	)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// validate returns an error if the network interface listeners configuration is
// invalid.
func (c *interfaceListenersConfig) validate() (err error) {
	switch {
	case c == nil:
		// This configuration is optional.
		//
		// TODO(a.garipov): Consider making required or not relying on nil
		// values.
		return nil
	case c.ChannelBufferSize <= 0:
		return newMustBePositiveError("channel_buffer_size", c.ChannelBufferSize)
	case len(c.List) == 0:
		return errors.Error("no list")
	default:
		// Go on.
	}

	err = mapsutil.SortedRangeError(
		c.List,
		func(id bindtodevice.ID, l *interfaceListener) (lsnrErr error) {
			return errors.Annotate(l.validate(), "interface %q: %w", id)
		},
	)

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

// validate returns an error if the interface listener configuration is invalid.
func (l *interfaceListener) validate() (err error) {
	switch {
	case l == nil:
		return errNilConfig
	case l.Port == 0:
		return errors.Error("port must not be zero")
	case l.Interface == "":
		return errors.Error("no interface")
	default:
		return nil
	}
}
