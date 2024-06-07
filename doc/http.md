 #  AdGuard DNS HTTP API

The main HTTP API is served on the same port as the DNS-over-HTTP servers as
well as on other addresses, if the [web configuration][conf-web] is set
appropriately.

##  Contents

 *  [Block Pages](#block-pages)
 *  [DNS Server Check](#dnscheck-test)
 *  [Linked IP Proxy](#linked-ip-proxy)
 *  [Static Content](#static-content)

[conf-web]: configuration.md#web



##  <a href="#block-pages" id="block-pages" name="block-pages">Block Pages</a>

The safe-browsing, adult-blocking, and popup-blocking servers.  Every request is
responded with the content from the configured file, with the exception of `GET
/favicon.ico` and `GET /robots.txt` requests, which are handled separately:

 *  `GET /favicon.ico` requests are responded with a plain-text `404 Not Found`
    response.

 *  `GET /robots.txt` requests are responded with:

    ```none
    User-agent: *
    Disallow: /
    ```

The [static content](#static-content) is not served on these servers.



##  <a href="#dnscheck-test" id="dnscheck-test" name="dnscheck-test">DNS Server Check</a>

`GET /dnscheck/test` is the DNS server check HTTP API.  It should be requested
with a random ID prepended to one of the [check domains][conf-check-domains]
with a hyphen.  The random ID must have from 4 to 63 characters and only include
the alphanumeric characters and a hyphen.

<!--
    TODO(a.garipov): Describe the check process in details.
-->

Example of the request:

```sh
curl 'https://0123-abcd-dnscheck.example.com/dnscheck/test'
```

Example of the output:

```json
{
  "client_ip": "1.2.3.4",
  "device_id": "abcd1234",
  "profile_id": "defa5678",
  "protocol": "dot",
  "node_location": "ams",
  "node_name": "eu-1.dns.example.com",
  "server_group_name": "adguard_dns_default",
  "server_name": "default_dns"
}
```

The `protocol` field can have one of the following values:

<dl>
    <dt>
        <code>"dns"</code>
    </dt>
    <dd>
        Plain DNS.
    </dd>
    <dt>
        <code>"dnscrypt"</code>
    </dt>
    <dd>
        DNSCrypt.
    </dd>
    <dt>
        <code>"doh"</code>
    </dt>
    <dd>
        DNS-over-HTTP.
    </dd>
    <dt>
        <code>"doq"</code>
    </dt>
    <dd>
        DNS-over-QUIC.
    </dd>
    <dt>
        <code>"dot"</code>
    </dt>
    <dd>
        DNS-over-TLS.
    </dd>
</dl>

[conf-check-domains]: configuration.md#check-domains



##  <a href="#linked-ip-proxy" id="linked-ip-proxy" name="linked-ip-proxy">Linked IP Proxy</a>

The linked IP and Dynamic DNS (DDNS, DynDNS) HTTP proxy.  If the [linked
IP configuration][conf-web-linked_ip] is not empty, the following queries are
either processed or proxied to [`LINKED_IP_TARGET_URL`][env-linked_ip_target_url].

 *  `GET  /robots.txt`: a special response is served, see below;
 *  `GET  /linkip/{device_id}/{encrypted}/status`: proxied;
 *  `GET  /linkip/{device_id}/{encrypted}`: proxied;
 *  `POST /ddns/{device_id}/{encrypted}/{domain}`: proxied;
 *  `POST /linkip/{device_id}/{encrypted}`: proxied.

In the case of a `GET /robots.txt` request, the following content is served:

```none
User-agent: *
Disallow: /
```

The [static content](#static-content) is not served on the linked IP addresses.

[conf-web-linked_ip]: configuration.md#web-linked_ip
[env-linked_ip_target_url]: environment.md#LINKED_IP_TARGET_URL



##  <a href="#static-content" id="static-content" name="static-content">Static Content</a>

The static content server.  Enabled if the [static content
configuration][conf-web-static_content] is not empty.  Static content is not
served on the linked IP proxy server and the safe browsing and adult blocking
servers.

[conf-web-static_content]: configuration.md#web-static_content
