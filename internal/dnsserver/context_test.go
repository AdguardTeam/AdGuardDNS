package dnsserver_test

import (
	"context"
	"testing"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver"
	"github.com/stretchr/testify/require"
)

func TestServerInfoFromContext(t *testing.T) {
	ctx := context.Background()
	_, ok := dnsserver.ServerInfoFromContext(ctx)
	require.False(t, ok)

	serverInfo := &dnsserver.ServerInfo{
		Name:  "test",
		Addr:  "127.0.0.1",
		Proto: dnsserver.ProtoDNS,
	}
	ctx = dnsserver.ContextWithServerInfo(ctx, serverInfo)

	s, ok := dnsserver.ServerInfoFromContext(ctx)
	require.True(t, ok)
	require.Equal(t, serverInfo, s)
}

func TestMustServerInfoFromContext(t *testing.T) {
	require.Panics(t, func() {
		ctx := context.Background()
		_ = dnsserver.MustServerInfoFromContext(ctx)
	})
}
