// Package filtertest contains common constants and utilities for the internal
// filtering packages.
package filtertest

import (
	"encoding/json"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/c2h5oh/datasize"
)

// Common rules for tests.
const (
	RuleBlockStr                 = "|" + HostBlocked + "^"
	RuleBlockForClientIPStr      = "|" + HostBlockedForClientIP + "^$client=" + IPv4ClientStr
	RuleBlockForClientNameStr    = "|" + HostBlockedForClientName + "^$client=" + ClientName
	RuleSafeSearchGeneralHostStr = "|" + HostSafeSearchGeneral + "^$dnsrewrite=NOERROR;CNAME;" +
		HostSafeSearchGeneralRepl
	RuleSafeSearchGeneralIPv4Str = "|" + HostSafeSearchGeneralIPv4 + "^$dnsrewrite=NOERROR;A;" +
		IPv4SafeSearchReplStr
	RuleSafeSearchGeneralIPv6Str = "|" + HostSafeSearchGeneralIPv6 + "^$dnsrewrite=NOERROR;AAAA;" +
		IPv6SafeSearchReplStr
	RuleSafeSearchYouTubeStr = "|" + HostSafeSearchYouTube + "^$dnsrewrite=NOERROR;CNAME;" +
		HostSafeSearchYouTubeRepl

	RuleBlock              filter.RuleText = RuleBlockStr
	RuleBlockForClientIP   filter.RuleText = RuleBlockForClientIPStr
	RuleBlockForClientName filter.RuleText = RuleBlockForClientNameStr
)

// Common string representations of IP addresses.
const (
	IPv4ClientStr           = "192.0.2.1"
	IPv4AdultContentReplStr = "192.0.2.2"
	IPv4SafeSearchReplStr   = "192.0.2.3"
	IPv6SafeSearchReplStr   = "2001:db8::1"
)

// Common IP addresses for tests.
var (
	IPv4Client           = netip.MustParseAddr(IPv4ClientStr)
	IPv4AdultContentRepl = netip.MustParseAddr(IPv4AdultContentReplStr)
	IPv4SafeSearchRepl   = netip.MustParseAddr(IPv4SafeSearchReplStr)
	IPv6SafeSearchRepl   = netip.MustParseAddr(IPv6SafeSearchReplStr)
)

// Common hostnames and FQDNs for tests.
const (
	Host                      = "host.example"
	HostAdultContent          = "adult-content.example"
	HostAdultContentSub       = "a.b.c." + HostAdultContent
	HostAdultContentRepl      = "adult-content-repl.example"
	HostBlocked               = "blocked.example"
	HostBlockedForClientIP    = "blocked-for-client-ip.example"
	HostBlockedForClientName  = "blocked-for-client-name.example"
	HostBlockedService1       = "service-1.example"
	HostCNAME                 = "new-cname.example"
	HostDangerous             = "dangerous-domain.example"
	HostDangerousRepl         = "dangerous-domain-repl.example"
	HostNewlyRegistered       = "newly-registered.example"
	HostNewlyRegisteredRepl   = "newly-registered-repl.example"
	HostSafeSearchGeneral     = "search-host.example"
	HostSafeSearchGeneralIPv4 = "search-ipv4.example"
	HostSafeSearchGeneralIPv6 = "search-ipv6.example"
	HostSafeSearchGeneralRepl = "safe.search.example"
	HostSafeSearchYouTube     = "video.example"
	HostSafeSearchYouTubeRepl = "safe.video.example"
	HostCategory              = "blocked.category.example"
	HostCategorySub           = "a.b.c." + HostCategory

	FQDN                      = Host + "."
	FQDNAdultContent          = HostAdultContent + "."
	FQDNAdultContentRepl      = HostAdultContentRepl + "."
	FQDNBlocked               = HostBlocked + "."
	FQDNBlockedForClientName  = HostBlockedForClientName + "."
	FQDNCname                 = HostCNAME + "."
	FQDNDangerous             = HostDangerous + "."
	FQDNDangerousRepl         = HostDangerousRepl + "."
	FQDNNewlyRegistered       = HostNewlyRegistered + "."
	FQDNNewlyRegisteredRepl   = HostNewlyRegisteredRepl + "."
	FQDNSafeSearchGeneralRepl = HostSafeSearchGeneralRepl + "."
	FQDNSafeSearchGeneralIPv4 = HostSafeSearchGeneralIPv4 + "."
	FQDNSafeSearchGeneralIPv6 = HostSafeSearchGeneralIPv6 + "."
	FQDNSafeSearchYouTube     = HostSafeSearchYouTube + "."
	FQDNSafeSearchYouTubeRepl = HostSafeSearchYouTubeRepl + "."
	FQDNCategory              = HostCategory + "."
)

// Common blocked-service IDs for tests.
const (
	BlockedServiceID1Str            = "blocked_service_1"
	BlockedServiceID2Str            = "blocked_service_2"
	BlockedServiceIDDoesNotExistStr = "blocked_service_none"

	BlockedServiceID1            filter.BlockedServiceID = BlockedServiceID1Str
	BlockedServiceID2            filter.BlockedServiceID = BlockedServiceID2Str
	BlockedServiceIDDoesNotExist filter.BlockedServiceID = BlockedServiceIDDoesNotExistStr
)

// BlockedServiceIndex is a service-index response for tests.
//
// See https://github.com/AdguardTeam/HostlistsRegistry/blob/main/assets/services.json.
const BlockedServiceIndex string = `{
  "blocked_services": [
    {
      "id": "` + BlockedServiceID1Str + `",
      "name": "Service 1",
      "rules": [
        "||` + HostBlockedService1 + `^"
      ]
    },
    {
      "id": "` + BlockedServiceID2Str + `",
      "name": "Service 2",
      "rules": [
        "||service-2.example^"
      ]
    }
  ]
}
`

// Common rule-list IDs for tests.
const (
	RuleListID1Str      = "rule_list_1"
	RuleListID2Str      = "rule_list_2"
	RuleListIDDomainStr = "blocked-category"

	RuleListID1      filter.ID = RuleListID1Str
	RuleListID2      filter.ID = RuleListID2Str
	RuleListIDDomain filter.ID = RuleListIDDomainStr

	CategoryIDStr                   = RuleListIDDomainStr
	CategoryID    filter.CategoryID = CategoryIDStr
)

// NewRuleListIndex returns a rule-list index containing a record for a filter
// with [RuleListID1Str] and downloadURL as the download URL.
func NewRuleListIndex(downloadURL string) (b []byte) {
	return errors.Must(json.Marshal(map[string]any{
		"filters": []map[string]any{{
			"filterKey":   RuleListID1Str,
			"downloadUrl": downloadURL,
		}},
	}))
}

// NewCategoryIndex returns a category rule-list index containing a filter for
// [CategoryIDStr] and downloadURL as the download URL.
func NewCategoryIndex(downloadURL string) (b []byte) {
	return errors.Must(json.Marshal(map[string]any{
		"filters": map[string]any{
			CategoryIDStr: map[string]any{
				"downloadUrl": downloadURL,
			},
		},
	}))
}

// CacheTTL is the common long cache-TTL for filtering tests.
const CacheTTL = 1 * time.Hour

// CacheCount is the common count of cache items for filtering tests.
const CacheCount = 100

// ClientName is the common client name for tests.
const ClientName = "MyDevice1"

// FilterMaxSize is the maximum size of the downloadable rule-list for filtering
// tests.
const FilterMaxSize = 640 * datasize.KB

// ServerName is the common server name for filtering tests.
const ServerName = "testServer/1.0"

// Staleness is the common long staleness files used in filtering tests.
const Staleness = 1 * time.Hour

// Timeout is the common timeout for filtering tests.
const Timeout = 1 * time.Second
