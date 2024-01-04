package forward

import (
	"context"
	"fmt"
	"io"

	"github.com/miekg/dns"
)

// Upstream is the interface for a DNS client.
type Upstream interface {
	// Exchange processes the given request.  Returns a response, network type
	// over which the request has been processed and an error if happened.
	//
	// TODO(a.garipov): Make it more extensible. Either metrics through context,
	// or returning some interface value, similar to [netext.PacketSession].
	Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, nw Network, err error)

	io.Closer
	fmt.Stringer
}
