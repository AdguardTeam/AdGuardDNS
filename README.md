&nbsp;
<p align="center">
  <img src="https://cdn.adguard.com/public/Adguard/Common/adguard_dns.svg" width="300px" alt="AdGuard Home" />
</p>
<h3 align="center">A new approach to privacy-oriented DNS</h3>
<p align="center">
    Public DNS resolver that protects you from ad trackers
</p>

<p align="center">
    <a href="https://adguard.com/">AdGuard.com</a> |
    <a href="https://reddit.com/r/Adguard">Reddit</a> |
    <a href="https://twitter.com/AdGuard">Twitter</a>
    <br /><br />
</p>

<p align="center">
    <img src="https://cdn.adguard.com/public/Adguard/Common/adguard_dns_map.png" width="800" />
</p>

# AdGuard DNS

AdGuard DNS is an alternative solution for trackers blocking, privacy protection, and parental control. Easy to set up and free to use, it provides a necessary minimum of best protection against online ads, trackers, and phishing, no matter what platform and device you use.

## DNS Privacy

If you use regular client-server protocol, you are at risk of your DNS requests being intercepted and, subsequently, eavesdropped and/or altered. For instance, in the US the Senate voted to eliminate rules that restricted ISPs from selling their users' browsing data. Moreover, DNS is often used for censorship and surveillance purposes on the government level. 

All of this is possible due to the lack of encryption, and AdGuard DNS provides a solution. It supports all known DNS encryption protocols including `DNS-over-HTTPS`, `DNS-over-TLS`, `DNS-over-QUIC`, and `DNSCrypt`.

On top of that, AdGuard DNS provides "no logs" [privacy policy](https://adguard.com/en/privacy/dns.html) which means we do not record logs of your browsing activity.

## Additional Features

* **Blocking trackers network-wide** with no additional software required. You can even set it up on your router to block ads on all devices connected to your home Wi-Fi network.
* Protection from phishing and hazardous websites and malvertising (malicious ads). 
* Use the **Family protection** mode of AdGuard DNS to block access to all websites with adult content and enforce safe search in the browser, in addition to the regular perks of ad blocking and browsing security.

**Can AdGuard DNS replace a traditional blocker?**

It depends. DNS-level blocking lacks the flexibility of the traditional ad blockers. For instance, there is no cosmetic pages processing. So in general, traditional blockers provide higher quality.

## Why is AdGuard DNS free? What’s the catch?

We use AdGuard DNS functionality as a part of other AdGuard software, most of which are distributed on a pay-to-use basis. We might also develop a paid version of AdGuard DNS based on the current one, more advanced and with more features.

## Usage

Please note that encrypted DNS protocols aren't supported at an operating system level so right now it requires the installation of additional software.

Here's a list of the software that could be used:

* Android 9 supports DNS-over-TLS natively
* [AdGuard for Android](https://adguard.com/en/adguard-android/overview.html) supports `DNS-over-HTTPS`, `DNS-over-TLS`, `DNS-over-QUIC`, and `DNSCrypt`
* [AdGuard for iOS Pro](https://adguard.com/en/adguard-ios-pro/overview.html) supports `DNSCrypt`
* [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) supports `DNS-over-HTTPS`, `DNS-over-TLS`, `DNS-over-QUIC`, and `DNSCrypt`
* [Intra](https://getintra.org/) supports `DNS-over-HTTPS`
* [Google Chrome](https://www.google.com/chrome/) supports `DNS-over-HTTPS`
* [Mozilla Firefox](https://www.mozilla.org/firefox/) supports `DNS-over-HTTPS`
* A lot more implementation can be [found here](https://dnscrypt.info/implementations) and [here](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Clients)

### Our server addresses

<details><summary>DNS-over-HTTPS</summary>

**Default server**

If you want to block ads and trackers.

`https://dns.adguard.com/dns-query`

**Non-filtering server**

If you don't want AdGuard DNS to block ads and trackers, or any other DNS requests.

`https://dns-unfiltered.adguard.com/dns-query`

**Family Protection server**

If you want to block adult content, enable safe search and safe mode options wherever possible, and also block ads and trackers.

`https://dns-family.adguard.com/dns-query`

</details>

<details><summary>DNS-over-TLS</summary>

**Default server**

If you want to block ads and trackers.

`dns.adguard.com`

**Non-filtering server**

If you don't want AdGuard DNS to block ads and trackers, or any other DNS requests.

`dns-unfiltered.adguard.com`

**Family Protection server**

If you want to block adult content, enable safe search and safe mode options wherever possible, and also block ads and trackers.

`dns-family.adguard.com`

</details>

<details><summary>DNS-over-QUIC</summary>

**Default server**

If you want to block ads and trackers.

`quic://dns.adguard.com`

**Non-filtering server**

If you don't want AdGuard DNS to block ads and trackers, or any other DNS requests.

`quic://dns-unfiltered.adguard.com`

**Family Protection server**

If you want to block adult content, enable safe search and safe mode options wherever possible, and also block ads and trackers.

`quic://dns-family.adguard.com`

</details>

<details><summary>DNSCrypt</summary>

**Default server**

If you want to block ads and trackers.

`sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20`

**Non-filtering server**

If you don't want AdGuard DNS to block ads and trackers, or any other DNS requests.

`sdns://AQMAAAAAAAAAEjk0LjE0MC4xNC4xNDA6NTQ0MyC16ETWuDo-PhJo62gfvqcN48X6aNvWiBQdvy7AZrLa-iUyLmRuc2NyeXB0LnVuZmlsdGVyZWQubnMxLmFkZ3VhcmQuY29t`

**Family Protection server**

If you want to block adult content, enable safe search and safe mode options wherever possible, and also block ads and trackers.

`sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNTo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ`

</details>

<details><summary>Plain DNS</summary>

**Default server**

If you want to block ads and trackers.

**IPv4:** `94.140.14.14` or `94.140.15.15`

**IPv6:** `2a10:50c0::ad1:ff` or `2a10:50c0::ad2:ff`

**Non-filtering server**

If you don't want AdGuard DNS to block ads and trackers, or any other DNS requests.

**IPv4:** `94.140.14.140` or `94.140.14.141`

**IPv6:** `2a10:50c0::1:ff` or `2a10:50c0::2:ff`

**Family Protection server**

If you want to block adult content, enable safe search and safe mode options wherever possible, and also block ads and trackers.

**IPv4:** `94.140.14.15` or `94.140.15.16`

**IPv6:** `2a10:50c0::bad1:ff` or `2a10:50c0::bad2:ff`

</details>

## Dependencies

AdGuard DNS shares a lot of code with [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) and uses pretty much [the same open source libraries](https://github.com/AdguardTeam/AdGuardHome#acknowledgments).

Additionally, AdGuard DNS is built on [CoreDNS](https://coredns.io/).

## Reporting issues

If you run into any problem or have a suggestion, head to [this page](https://github.com/AdguardTeam/AdGuardDNS/issues) and click on the New issue button.
