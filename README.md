&nbsp;
<p align="center">
  <img src="https://cdn.adguard.com/public/Adguard/Common/adguard_dns.svg" width="300px" alt="AdGuard Home" />
</p>
<h3 align="center">A new approach to privacy-oriented DNS</h3>
<p align="center">
    Public DNS resolver that protects you from ad trackers
</p>

<p align="center">
    <a href="https://adguard-dns.com/">AdGuard DNS Website</a> |
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

All of this is possible due to the lack of encryption, and AdGuard DNS provides a solution. It supports all known DNS encryption protocols including `DNS-over-HTTPS`, `DNS-over-TLS`, and `DNSCrypt`.

On top of that, AdGuard DNS provides "no logs" [privacy policy](https://adguard.com/en/privacy/dns.html) which means we do not record logs of your browsing activity.

## Additional Features

* **Blocking trackers network-wide** with no additional software required. You can even set it up on your router to block ads on all devices connected to your home Wi-Fi network.
* Protection from phishing and hazardous websites and malvertising (malicious ads). 
* Use the **Family protection** mode of AdGuard DNS to block access to all websites with adult content and enforce safe search in the browser, in addition to the regular perks of ad blocking and browsing security.

**Can AdGuard DNS replace a traditional blocker?**
<br/>
It depends. DNS-level blocking lacks the flexibility of the traditional ad blockers. For instance, there is no cosmetic pages processing. So in general, traditional blockers provide higher quality.

## Why is AdGuard DNS free? What’s the catch?

We use AdGuard DNS functionality as a part of other AdGuard software, most of which are distributed on a pay-to-use basis. We might also develop a paid version of AdGuard DNS based on the current one, more advanced and with more features.

## Usage

Please note that encrypted DNS protocols aren't supported at an operating system level so right now it requires the installation of additional software.

Here's a list of the software that could be used:

* Android 9 supports DNS-over-TLS natively
* [AdGuard for Android](https://adguard.com/en/adguard-android/overview.html) supports `DNSCrypt` in the stable version, and supports `DNS-over-HTTPS` in the [nightly update channel](https://adguard.com/beta.html)
* [AdGuard for iOS Pro](https://adguard.com/en/adguard-ios-pro/overview.html) supports `DNSCrypt`
* [Intra](https://getintra.org/) adds `DNS-over-HTTPS` support to Android
* [Mozilla Firefox](https://www.mozilla.org/firefox/) supports `DNS-over-HTTPS`
* [AdGuard Home](https://github.com/AdguardTeam/AdguardHome) supports `DNS-over-TLS` and `DNS-over-HTTPS`
* A lot more implementation can be [found here](https://dnscrypt.info/implementations) and [here](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Clients)

### Regular DNS

* `94.140.14.14` or `94.140.15.15` for "Default";
* `94.140.14.15` or `94.140.15.16` for "Family protection";
* `94.140.14.140` or `94.140.14.141` for "Non-filtering".

### DNS-over-HTTPS

* Use `https://dns.adguard.com/dns-query` for "Default";
* Use `https://dns-family.adguard.com/dns-query` for "Family protection" mode;
* Use `https://dns-unfiltered.adguard.com/dns-query` for "Non-filtering" mode;

### DNS-over-TLS

* Use `dns.adguard.com` string for "Default";
* Use `dns-family.adguard.com` for "Family protection";
* Use `dns-unfiltered.adguard.com` for "Non-filtering";

### DNSCrypt

"Default":
`sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20`

"Family protection":
`sdns://AQIAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzMjo1NDQzILgxXdexS27jIKRw3C7Wsao5jMnlhvhdRUXWuMm1AFq6ITIuZG5zY3J5cHQuZmFtaWx5Lm5zMS5hZGd1YXJkLmNvbQ`

"Non-filtering":
`sdns://AQcAAAAAAAAAFDE3Ni4xMDMuMTMwLjEzNjo1NDQzILXoRNa4Oj4-EmjraB--pw3jxfpo29aIFB2_LsBmstr6JTIuZG5zY3J5cHQudW5maWx0ZXJlZC5uczEuYWRndWFyZC5jb20`

## Dependencies

AdGuard DNS shares a lot of code with [AdGuard Home](https://github.com/AdguardTeam/AdGuardHome) and uses pretty much [the same open source libraries](https://github.com/AdguardTeam/AdGuardHome#acknowledgments).

Additionally, AdGuard DNS is built on [CoreDNS](https://coredns.io/).

## Reporting issues

If you run into any problem or have a suggestion, head to [this page](https://github.com/AdguardTeam/AdGuardDNS/issues) and click on the New issue button.
