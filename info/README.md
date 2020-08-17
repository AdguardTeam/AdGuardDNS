# Info

This plugin makes it possible to check what AdGuard DNS server is in use.

```
    info {
        domain adguard.com
        type unfiltered
        protocol auto
        addr 176.103.130.136 176.103.130.137
        canary dnscheck.adguard.com
    }
```

Discovery requests look like: `*-{protocol}-{type}-dnscheck.{domain}`.
For instance, `12321-doh-unfiltered-dnscheck.adguard.com`. If the domain is queried
using `doh` protocol from a server with type `unfiltered`, the request will return
the specified `addr`. Otherwise, it will return `NXDOMAIN`.

* `domain` - registered domain that will be used in the discovery DNS queries.
* `type` - server type (any string).
* `protocol` - possible values are `dns`, `doh`, `dot`, `dnscrypt`, `auto`.
    
    If it's set to `auto`, the plugin will try to detect the protocol by itself.
    If it's set to a specific protocol, the plugin won't try to detect anything.  
    
* `addr` - the list of addresses to return in the discovery response.
You can specify multiple addresses here.
IPv4 addresses will be used for A responses, IPv6 - for AAAA.
* `canary` - (optional) simple "canary" domain which only purpose is to test whether AdGuard DNS
is enabled or not without any additional logic (protocol or type detection) on top of it.

> Note: canary domain is used by third-party services that may want to discover if AdGuard DNS is used or not.
> For instance, Keenetic routers use it.