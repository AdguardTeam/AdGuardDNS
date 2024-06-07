 #  AdGuard DNS Query Log Format

The query log is written in the [JSONL][jsonl] (JSON Lines) format.  The log
entries are designed to be concise and easily compressable.  An example of the
log output:

```jsonl
{"u":"ABCD","b":"prof1234","i":"dev1234","c":"RU","d":"US","n":"example.com.","l":"cdef5678","m":"||example.com^","t":1628590394000,"a":1234,"e":5,"q":1,"rn":1234,"f":2,"s":0,"p":8,"r":0}
{"u":"DEFG","b":"prof1234","i":"dev1234","c":"RU","d":"JP","n":"example.org.","l":"hijk9012","m":"||example.org^","t":1628590394100,"a":6789,"e":6,"q":1,"rn":56789,"f":2,"s":0,"p":8,"r":0}
```

AdGuard DNS opens and closes the log file on each write to prevent issues with
external log rotation.

[jsonl]: https://jsonlines.org/



##  <a href="#properties" id="properties" name="properties">Properties</a>

Property names have been chosen to be single-letter but still have mnemonic
rules to remember, which property means what.  The properties are:

 *  <a href="#properties-u" id="properties-u" name="properties-u">`u`</a>:
    The unique ID of the request.  The short name `u` stands for “unique”.

     >  [!NOTE]
     >  This field is deprecated and may be removed in the future.

    **Example:** `"ABCD1234"`

 *  <a href="#properties-b" id="properties-b" name="properties-b">`b`</a>:
    The detected profile ID (also known as DNS ID and DNS Server ID), if any.
    The short name `b` stands for “buyer”.

    **Example:** `"prof1234"`

 *  <a href="#properties-i" id="properties-i" name="properties-i">`i`</a>:
    The detected device ID, if any.  The short name `i` stands for “ID”.

    **Example:** `"dev1234"`

 *  <a href="#properties-c" id="properties-c" name="properties-c">`c`</a>:
    The detected country of the client's IP address as an [ISO 3166-1
    alpha-2][wiki-iso] country code, if any.  If none could be detected, this
    property is absent.  The short name `c` stands for “client country”.

     >  [!NOTE]
     >  AdGuard DNS uses the common user-assigned ISO 3166-1 alpha-2 code `XK`
     >  for the partially-recognized state of the Republic of Kosovo.

    **Example:** `"AU"`

 *  <a href="#properties-d" id="properties-d" name="properties-d">`d`</a>:
    The detected country of the first IP address in the response sent to the
    client, as an [ISO 3166-1 alpha-2][wiki-iso] country code, if any.  If none
    could be detected, this property is absent.  The short name `d` stands for
    “destination”.

     >  [!NOTE]
     >  AdGuard DNS uses the common user-assigned ISO 3166-1 alpha-2 code `XK`
     >  for the partially-recognized state of the Republic of Kosovo.

    **Example:** `"US"`

 *  <a href="#properties-n" id="properties-n" name="properties-n">`n`</a>:
    The requested resource name.  The short name `n` stands for “name”.

    **Example:** `"example.com."`

 *  <a href="#properties-l" id="properties-l" name="properties-l">`l`</a>:
    The ID of the first filter the rules of which matched this query.  If no
    rules matched, this property is omitted.  The short name `l` stands for
    “list of filter rules”.

    **Example:** `"adguard_dns_filter"`

    The special reserved values are:

     *  `blocked_service`: the request was blocked by the service blocker.  The
        property `m` contains the ID of that blocked service.

     *  `custom`: the request was filtered by a custom profile rule.

     *  `adult_blocking`: the request was filtered by the adult content blocking
        filter.

     *  `safe_browsing`: the request was filtered by the safe browsing filter.

     *  `general_safe_search`: the request was modified by the general safe
        search filter.

     *  `youtube_safe_search`: the request was modified by the YouTube safe
        search filter.

 *  <a href="#properties-m" id="properties-m" name="properties-m">`m`</a>:
    The text of the first rule that matched this query or the ID of the blocked
    service, if the ID of the filtering rule list is `blocked_service`.  If no
    rules matched, this property is omitted.  The short name `m` stands for
    “match”.

    **Object examples:**

    ```json
    {
      "l": "adguard_dns_filter",
      "m": "||example.com^",
      "...": "..."
    }
    ```

    ```json
    {
      "l": "blocked_service",
      "m": "example",
      "...": "..."
    }
    ```

 *  <a href="#properties-t" id="properties-t" name="properties-t">`t`</a>:
    The [Unix time][wiki-unix] at which the request was received, in
    milliseconds.  The short name `t` stands for “time”.

    **Example:** `1629974298000`

 *  <a href="#properties-a" id="properties-a" name="properties-a">`a`</a>:
    The detected [autonomous system][wiki-asn] number (aka ASN) of the client's
    IP address, if any.  If none could be detected, this property is absent.
    The short name `a` stands for “ASN”.

    **Example:** `1234`

 *  <a href="#properties-e" id="properties-e" name="properties-e">`e`</a>:
    The time passed since the beginning of the request processing, in
    milliseconds.  The short name `e` stands for “elapsed”.

    **Example:** `3`

 *  <a href="#properties-q" id="properties-q" name="properties-q">`q`</a>:
    The type of the resource record of the query.  The short name `q` stands for
    “question”.

    **Example:** `1`

    See [this Wikipedia list][wiki-dnsrr] for numeric values and their meanings.

 *  <a href="#properties-rn" id="properties-rn" name="properties-rn">`rn`</a>:
    A random 16-bit unsigned integer added to an entry for easier deduplication
    when `"u"` is not used for that.

    **Example:** `12345`

 *  <a href="#properties-f" id="properties-f" name="properties-f">`f`</a>:
    The action taken with this request.  The short name `f` stands for
    “filtering”.  The possible values are:

    <dl>
        <dt>
            <code>0</code>
        </dt>
        <dd>
            Invalid or unknown action.  Typically, this value is never used.
        </dd>
        <dt>
            <code>1</code>
        </dt>
        <dd>
            No filtering.
        <dt>
            <code>2</code>
        </dt>
        <dd>
            The request (question) is blocked.
        </dd>
        <dt>
            <code>3</code>
        </dt>
        <dd>
            The response (answer) is blocked.
        </dd>
        <dt>
            <code>4</code>
        </dt>
        <dd>
            The request (question) is allowed by an allowlist rule.
        </dd>
        <dt>
            <code>5</code>
        </dt>
        <dd>
            The response (answer) is allowed by an allowlist rule.
        </dd>
        <dt>
            <code>6</code>
        </dt>
        <dd>
            The request (question) or response (answer) was modified or
            rewritten by a safety filter or a DNS rewrite rule.
        </dd>
    </dl>

    **Example:** `2`

 *  <a href="#properties-s" id="properties-s" name="properties-s">`s`</a>:
    The status of whether the response was validated with DNSSEC.  `0` means no,
    `1` means yes.  The short name `s` stands for “secure”.

    **Example:** `1`

 *  <a href="#properties-p" id="properties-p" name="properties-p">`p`</a>:
    The DNS protocol used to process this request.  The short name `p` stands
    for “protocol”.  The possible values are:

    <dl>
        <dt>
            <code>0</code>
        </dt>
        <dd>
            Invalid or unknown protocol.  Typically, this value is never used.
        </dd>
        <dt>
            <code>3</code>
        </dt>
        <dd>
            DNS-over-HTTPS.
        </dd>
        <dt>
            <code>4</code>
        </dt>
        <dd>
            DNS-over-QUIC.
        </dd>
        <dt>
            <code>5</code>
        </dt>
        <dd>
            DNS-over-TLS.
        </dd>
        <dt>
            <code>8</code>
        </dt>
        <dd>
            Plain DNS.
        </dd>
        <dt>
            <code>9</code>
        </dt>
        <dd>
            DNSCrypt.
        </dd>
    </dl>

    **Example:** `3`

 *  <a href="#properties-r" id="properties-r" name="properties-r">`r`</a>:
    The response code (aka `RCODE`) sent to the client.  The short name `r`
    stands for “response”.

    **Example:** `0`

    See [this IANA list][iana-rcode] for numeric values and their meanings.

 *  <a href="#properties-ip" id="properties-ip" name="properties-ip">`ip`</a>:
    The IP address of the client.  This field is omitted in case the IP logging
    is turned off for the corresponding profile.  The short name `ip` stands for
    “IP”.

    **Example:** `1.2.3.4`

See also [file `internal/querylog/entry.go`][file-entry.go] for an explanation
of the properties, their names, and mnemonics.

[file-entry.go]: ../internal/querylog/entry.go
[iana-rcode]:    https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
[wiki-asn]:      https://en.wikipedia.org/wiki/Autonomous_system_(Internet)
[wiki-dnsrr]:    https://en.wikipedia.org/wiki/List_of_DNS_record_types
[wiki-iso]:      https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2
[wiki-unix]:     https://en.wikipedia.org/wiki/Unix_time
