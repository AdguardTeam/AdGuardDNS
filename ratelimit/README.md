# ratelimit

This plugin allows to configure an arbitrary rate limit for the DNS server.

```
ratelimit [RPS] [BACKOFF_LIMIT] {
    whitelist [[ADDR1], ..., ADDRN]
    consul URL TTL
}
```

* `[RPS]` - maximum number of requests per second
* `[BACKOFF_LIMIT]` - supposed to help with repeated offenders. If some IP gets rate-limited for more than `[BACKOFF_LIMIT]` times in 30 minutes, this IP will be blocked until this 30 mins period ends.
* `whitelist` -- allows to configure IP addresses excluded from the ratelimit.
* `consul` -- allows to use Consul as a source for the whitelisted IP addresses.

    The first parameter is the URL where the plugin can download services list from.
    The second parameter is TTL of this list in seconds. The plugin will reload it automatically.