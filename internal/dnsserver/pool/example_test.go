package pool_test

import (
	"context"
	"net"

	"github.com/AdguardTeam/AdGuardDNS/internal/dnsserver/pool"
)

func ExampleNewPool() {
	f := pool.Factory(func(_ context.Context) (net.Conn, error) {
		return net.Dial("udp", "8.8.8.8:53")
	})
	p := pool.NewPool(10, f)

	// Create a new connection or get it from the pool
	conn, err := p.Get(context.Background())
	if err != nil {
		panic("cannot create a new connection")
	}

	// Put the connection back to the pool when it's not needed anymore
	err = p.Put(conn)
	if err != nil {
		panic("cannot put connection back to the pool")
	}

	// Close the pool when you don't need it anymore
	err = p.Close()
	if err != nil {
		panic("cannot close the pool")
	}

	// Output:
}
