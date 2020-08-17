## Patches

Some of the vendored dependencies were patched.

1. request.go -- always compress responses

    ```
    diff --git a/vendor/github.com/coredns/coredns/request/request.go b/vendor/github.com/coredns/coredns/request/request.go
    index 7374b0b..268b008 100644
    --- a/vendor/github.com/coredns/coredns/request/request.go
    +++ b/vendor/github.com/coredns/coredns/request/request.go
    @@ -219,27 +219,7 @@ func (r *Request) SizeAndDo(m *dns.Msg) bool {
     // get the bit, the client should then retry with pigeons.
     func (r *Request) Scrub(reply *dns.Msg) *dns.Msg {
            reply.Truncate(r.Size())
    -
    -       if reply.Compress {
    -               return reply
    -       }
    -
    -       if r.Proto() == "udp" {
    -               rl := reply.Len()
    -               // Last ditch attempt to avoid fragmentation, if the size is bigger than the v4/v6 UDP fragmentation
    -               // limit and sent via UDP compress it (in the hope we go under that limit). Limits taken from NSD:
    -               //
    -               //    .., 1480 (EDNS/IPv4), 1220 (EDNS/IPv6), or the advertised EDNS buffer size if that is
    -               //    smaller than the EDNS default.
    -               // See: https://open.nlnetlabs.nl/pipermail/nsd-users/2011-November/001278.html
    -               if rl > 1480 && r.Family() == 1 {
    -                       reply.Compress = true
    -               }
    -               if rl > 1220 && r.Family() == 2 {
    -                       reply.Compress = true
    -               }
    -       }
    -
    +       reply.Compress = true
            return reply
     }

    ```

2. `forward` plugin fork

    Exposed `parseStanza` to our "alternate" plugin fork.
    
    ```
    // Exposed to our "alternate" plugin
    func ParseForwardStanza(c *caddy.Controller) (*Forward, error) {
        return parseStanza(c)
    }
    ```

3. "alternate" plugin fork

    Use our "forward" plugin fork instead of the original "forward".

4. "health" plugin fork

    Use "/health-check" instead of "/health"