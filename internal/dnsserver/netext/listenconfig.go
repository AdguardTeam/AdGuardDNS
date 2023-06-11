// Package netext contains extensions of package net in the Go standard library.
package netext

import (
	"context"
	"fmt"
	"net"
	"syscall"
)

// ListenConfig is the interface that allows controlling options of connections
// used by the DNS servers defined in this module.  Default ListenConfigs are
// the ones returned by [DefaultListenConfigWithOOB] for plain DNS and
// [DefaultListenConfig] for others.
//
// This interface is modeled after [net.ListenConfig].
type ListenConfig interface {
	Listen(ctx context.Context, network, address string) (l net.Listener, err error)
	ListenPacket(ctx context.Context, network, address string) (c net.PacketConn, err error)
}

// defaultCtrlConf is the default control config.  By default, don't alter
// anything.  defaultCtrlConf must not be mutated.
var defaultCtrlConf = &ControlConfig{
	RcvBufSize: 0,
	SndBufSize: 0,
}

// DefaultListenConfig returns the default [ListenConfig] used by the servers in
// this module except for the plain-DNS ones, which use
// [DefaultListenConfigWithOOB].  If conf is nil, a default configuration is
// used.
func DefaultListenConfig(conf *ControlConfig) (lc ListenConfig) {
	if conf == nil {
		conf = defaultCtrlConf
	}

	return &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) (err error) {
			return listenControlWithSO(conf, c)
		},
	}
}

// DefaultListenConfigWithOOB returns the default [ListenConfig] used by the
// plain-DNS servers in this module.  The resulting ListenConfig sets additional
// socket flags and processes the control-messages of connections created with
// ListenPacket.  If conf is nil, a default configuration is used.
func DefaultListenConfigWithOOB(conf *ControlConfig) (lc ListenConfig) {
	if conf == nil {
		conf = defaultCtrlConf
	}

	return &listenConfigOOB{
		ListenConfig: net.ListenConfig{
			Control: func(_, _ string, c syscall.RawConn) (err error) {
				return listenControlWithSO(conf, c)
			},
		},
	}
}

// type check
var _ ListenConfig = (*listenConfigOOB)(nil)

// listenConfigOOB is a wrapper around [net.ListenConfig] with modifications
// that set the control-message options on packet conns.
type listenConfigOOB struct {
	net.ListenConfig
}

// ListenPacket implements the [ListenConfig] interface for *listenConfigOOB.
// It sets the control-message flags to receive additional out-of-band data to
// correctly discover the source address when it listens to 0.0.0.0 as well as
// in situations when SO_BINDTODEVICE is used.
//
// network must be "udp", "udp4", or "udp6".
func (lc *listenConfigOOB) ListenPacket(
	ctx context.Context,
	network string,
	address string,
) (c net.PacketConn, err error) {
	c, err = lc.ListenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	err = setIPOpts(c)
	if err != nil {
		return nil, fmt.Errorf("setting socket options: %w", err)
	}

	return wrapPacketConn(c), nil
}

// ControlConfig is the configuration of socket options.
type ControlConfig struct {
	// RcvBufSize defines the size of socket receive buffer in bytes.  Default
	// is zero (uses system settings).
	RcvBufSize int

	// SndBufSize defines the size of socket send buffer in bytes.  Default is
	// zero (uses system settings).
	SndBufSize int
}
