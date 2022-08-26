package forward

import (
	"context"
	"fmt"
	"io"

	"github.com/miekg/dns"
)

// Upstream is the interface for a DNS client.
type Upstream interface {
	Exchange(ctx context.Context, req *dns.Msg) (resp *dns.Msg, err error)
	io.Closer
	fmt.Stringer
}
