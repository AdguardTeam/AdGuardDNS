# dnsfilter

This plugin implements the filtering logic.

It uses local blacklists to make a decision on whether the DNS request should be blocked or bypassed.

```
dnsfilter {
    filter [PATH] [URL TTL]
    safebrowsing [PATH] [HOST] [URL TTL]
    parental [PATH] [HOST] [URL TTL]
    safesearch
}
```

* `filter [PATH]` -- path to the blacklist that will be used for blocking ads and trackers
* `filter [URL TTL]` -- URL to the filter list and TTL. Once in in `TTL` seconds we will
    try to reload the filter from the specified URL.  
* `safebrowsing [PATH] [HOST]`
    * path to the blacklist that will be used for blocking malicious/phishing domains
    * hostname that we will use for DNS response when we block malicious/phishing domains
* `parental [PATH] [HOST]`
    * path to the blacklist that will be used for blocking adult websites
    * hostname that we will use for DNS response when we block adult websites
* `safesearch` - if specified, we'll enforce safe search on the popular search engines
