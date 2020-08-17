package util

import (
	"context"

	"github.com/coredns/coredns/core/dnsserver"
)

// GetServer gets server address from the context
func GetServer(ctx context.Context) string {
	srv := ctx.Value(dnsserver.Key{})
	if srv == nil {
		return ""
	}

	return srv.(*dnsserver.Server).Addr
}
