# AdGuard DNS query debugging API

<!-- markdownlint-disable MD010 -->

You can debug AdGuard DNS queries by performing a query with the `CHAOS` class:

```sh
dig CH A 'example.com' @dns.adguard-dns.com
```

An example of the reply from AdGuard DNS:

```none
;; Warning: Message parser reports malformed message packet.

; <<>> DiG 9.10.6 <<>> @127.0.0.1 -p 8182 example.com CH
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 40344
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 3

;; OPT PSEUDOSECTION:
; EDNS: version: 0, flags: do; udp: 4096
;; QUESTION SECTION:
;example.com.			CH	A

;; ANSWER SECTION:
example.com.		17597	IN	A	93.184.216.34

;; ADDITIONAL SECTION:
client-ip.adguard-dns.com. 10	CH	TXT	"127.0.0.1"
server-ip.adguard-dns.com. 10	CH	TXT	"94.140.14.14"
node-name.adguard-dns.com. 10	CH	TXT	"lon-1"
resp.res-type.adguard-dns.com. 10 CH TXT	"normal"

;; Query time: 26 msec
;; SERVER: dns.adguard-dns.com#53(127.0.0.1)
;; WHEN: Wed Oct 27 16:54:47 MSK 2021
;; MSG SIZE  rcvd: 166
```

In the `ANSWER SECTION`, the usual `IN` reply is returned.

In the `ADDITIONAL SECTION`, the following debug information is returned:

- <a href="#additional-client-ip" id="additional-client-ip" name="additional-client-ip">`client-ip`</a>: The IP address of the client. The full name is `client-ip.adguard-dns.com`.

    **Example:**

    ```none
    client-ip.adguard-dns.com. 10	CH	TXT	"127.0.0.1"
    ```

- <a href="#additional-server-ip" id="additional-server-ip" name="additional-server-ip">`server-ip`</a>: The IP address of the server. The full name is `server-ip.adguard-dns.com`.

    **Example:**

    ```none
    server-ip.adguard-dns.com. 10	CH	TXT	"127.0.0.1"
    ```

- <a href="#additional-node-name" id="additional-node-name" name="additional-node-name">`additional-node-name`</a>: The name of this server node. The full name is `node-name.adguard-dns.com`.

  **Example:**

    ```none
    node-name.adguard-dns.com. 10	CH	TXT	"lon-1"
    ```

- <a href="#additional-device-id" id="additional-device-id" name="additional-device-id">`device-id`</a>: The ID of the device as detected by the server, if any. The full name is `device-id.adguard-dns.com`.

    **Example:**

    ```none
    device-id.adguard-dns.com. 10	CH	TXT	"dev1234"
    ```

- <a href="#additional-profile-id" id="additional-profile-id" name="additional-profile-id">`profile-id`</a>: The ID of the profile (aka “DNS server” on the UI) of the AdGuard DNS server. The full name is `profile-id.adguard-dns.com`.

    **Example:**

    ```none
    profile-id.adguard-dns.com. 10	CH	TXT	"prof1234"
    ```

- <a href="#additional-country" id="additional-country" name="additional-country">`country`</a>: User's country code. The full name is `country.adguard-dns.com`.

    **Example:**

    ```none
    country.adguard-dns.com.	10 CH	TXT	"CY"
    ```

- <a href="#additional-asn" id="additional-asn" name="additional-asn">`asn`</a>: User's autonomous system number (ASN). The full name is `asn.adguard-dns.com`.

    **Example:**

    ```none
    asn.adguard-dns.com.	10 CH	TXT	"1234"
    ```

- <a href="#additional-subdivision" id="additional-subdivision" name="additional-subdivision">`subdivision`</a>: User's location subdivision code. This field could be empty even if user's country code is present. The full name is `subdivision.adguard-dns.com`.

   **Example:**

   ```none
   country.adguard-dns.com.	10 CH	TXT	"US"
   subdivision.adguard-dns.com. 10 CH	TXT	"CA"
   ```

The following debug records can have one of two prefixes: `req` or `resp`. The prefix depends on whether the filtering was applied to the request or the response.

- <a href="#additional-res-type" id="additional-res-type" name="additional-res-type">`res-type`</a>: The `type` of response. The full name is `(req|resp).res-type.adguard-dns.com`. Can be the following types:

    - <a href="#additional-res-type-normal" id="additional-res-type-normal" name="additional-res-type-normal">`normal`</a>: The request or response was not filtered.

    - <a href="#additional-res-type-blocked" id="additional-res-type-blocked" name="additional-res-type-blocked">`blocked`</a>: The request or response was blocked by a filter list or parental protection.

    - <a href="#additional-res-type-allowed" id="additional-res-type-allowed" name="additional-res-type-allowed">`allowed`</a>: The request or response was allowed by an exception rule.

    - <a href="#additional-res-type-modified" id="additional-res-type-modified" name="additional-res-type-modified">`modified`</a>: The query has been rewritten by a rewrite rule or parental protection.

    **Example:**

    ```none
    req.res-type.adguard-dns.com. 10 CH	TXT	"blocked"
    ```

- <a href="#additional-rule" id="additional-rule" name="additional-rule">`rule`</a>: The rule that was applied to the query. The full name is `(req|resp).rule.adguard-dns.com`. Rules that are longer than 255 bytes are split into several consecutive strings.

    **Example:**

    Rule shorter than 255 bytes:

    ```none
    req.rule.adguard-dns.com.	10 CH	TXT	"||example.com^"
    ```

    Rule longer than 255 bytes:

    ```none
    req.rule.adguard-dns.com. 0 CH TXT "||heregoesthefirstpartoftherule"
    "heregoesthesecondpartoftherule"
    ```

- <a href="#additional-rule-list-id" id="additional-rule-list-id" name="additional-rule-list-id">`rule-list-id`</a>: The ID of the rule list that was applied, if any. The full name is `(req|resp).rule-list-id.adguard-dns.com`.

    **Example:**

    ```none
    req.rule-list-id.adguard-dns.com.	10 CH	TXT	"adguard_dns_filter"
    ```

The TTL of these responses is taken from parameter [`filters.response_ttl`][conf-filters-ttl] in the configuration file.

[conf-filters-ttl]: configuration.md#filters-response_ttl
