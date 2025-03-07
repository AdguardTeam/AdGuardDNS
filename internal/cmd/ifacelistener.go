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
	"github.com/AdguardTeam/golibs/validate"
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
var _ validate.Interface = (*interfaceListenersConfig)(nil)

// Validate implements the [validate.Interface] interface for
// *interfaceListenersConfig.
func (c *interfaceListenersConfig) Validate() (err error) {
	if c == nil {
		// This configuration is optional.
		//
		// TODO(a.garipov): Consider making required or not relying on nil
		// values.
		return nil
	}

	errs := []error{
		validate.Positive("channel_buffer_size", c.ChannelBufferSize),
	}

	// TODO(a.garipov):  Consider adding validate.NotEmptyMap.
	if len(c.List) == 0 {
		errs = append(errs, fmt.Errorf("list: %w", errors.ErrEmptyValue))
	}

	// TODO(a.garipov):  Consider adding validate.Map.
	for _, id := range slices.Sorted(maps.Keys(c.List)) {
		err = c.List[id].Validate()
		if err != nil {
			errs = append(errs, fmt.Errorf("interface %q: %w", id, err))
		}
	}

	return errors.Join(errs...)
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
var _ validate.Interface = (*interfaceListener)(nil)

// Validate implements the [validate.Interface] interface for
// *interfaceListener.
func (l *interfaceListener) Validate() (err error) {
	if l == nil {
		return errors.ErrNoValue
	}

	return errors.Join(
		validate.Positive("port", l.Port),
		validate.NotEmpty("interface", l.Interface),
	)
}
