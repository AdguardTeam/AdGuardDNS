package dnsfilter

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"sort"
	"strconv"
	"strings"
	"time"

	safeservices "github.com/AdguardTeam/AdGuardDNS/dnsfilter/safe_services"
	"github.com/AdguardTeam/urlfilter/filterlist"

	"github.com/joomcode/errorx"

	"github.com/AdguardTeam/urlfilter"
	"github.com/caddyserver/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func init() {
	caddy.RegisterPlugin("dnsfilter", caddy.Plugin{
		ServerType: "dns",
		Action:     setup,
	})
}

// plugSettings is the dnsfilter plugin settings
type plugSettings struct {
	SafeSearchEnabled bool // If true -- safe search is enabled

	SafeBrowsingEnabled    bool   // If true -- check requests against the safebrowsing filter list
	SafeBrowsingBlockHost  string // Hostname to use for requests blocked by safebrowsing
	SafeBrowsingFilterPath string // Path to the safebrowsing filter list

	ParentalEnabled    bool   // If true -- check requests against the parental filter list
	ParentalBlockHost  string // Hostname to use for requests blocked by parental control
	ParentalFilterPath string // Path to the parental filter list

	BlockedTTL  uint32   // in seconds, default 3600
	FilterPaths []string // List of filter lists for blocking ad/tracker request

	// Update - map of update info for the filter lists
	// It includes safebrowsing and parental filter lists
	// Key is path to the filter list file
	Update map[string]*updateInfo

	// filterPathsKey is a key for the enginesMap to store the blockFilterEngine.
	// it is composed from sorted FilterPaths joined by '#'
	filterPathsKey string
}

// plug represents the plugin itself
type plug struct {
	Next     plugin.Handler
	settings plugSettings
}

// Name returns name of the plugin as seen in Corefile and plugin.cfg
func (p *plug) Name() string { return "dnsfilter" }

func setup(c *caddy.Controller) error {
	clog.Infof("Initializing the dnsfilter plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	p, err := setupPlugin(c)
	if err != nil {
		return err
	}
	config := dnsserver.GetConfig(c)
	config.AddPlugin(func(next plugin.Handler) plugin.Handler {
		p.Next = next
		return p
	})

	c.OnStartup(func() error {
		metrics.MustRegister(c, requests, filtered, filteredLists, filteredSafeBrowsing,
			filteredParental, safeSearch, errorsTotal,
			requestsSafeBrowsingTXT, requestsParentalTXT,
			elapsedTime, elapsedFilterTime,
			engineTimestamp, engineSize, engineStatus,
			statsCacheSize, statsUploadTimestamp, statsUploadStatus)
		// Set to 1 by default
		statsUploadStatus.Set(float64(1))
		return nil
	})
	clog.Infof("Finished initializing the dnsfilter plugin for %s", c.ServerBlockKeys[c.ServerBlockKeyIndex])
	return nil
}

// setupPlugin initializes the CoreDNS plugin
func setupPlugin(c *caddy.Controller) (*plug, error) {
	settings, err := parseSettings(c)
	if err != nil {
		return nil, err
	}

	// It's important to call it before the initEnginesMap
	// Because at this point we may need to download filter lists
	// and this must be done before we attempt to init engines
	err = initUpdatesMap(settings)
	if err != nil {
		return nil, err
	}

	err = initEnginesMap(settings)
	if err != nil {
		return nil, err
	}

	clog.Infof("Initialized dnsfilter settings for server block %d", c.ServerBlockIndex)
	return &plug{settings: settings}, nil
}

func parseSettings(c *caddy.Controller) (plugSettings, error) {
	settings := defaultPluginSettings

	for c.Next() {
		for c.NextBlock() {
			blockValue := c.Val()
			switch blockValue {
			case "safebrowsing":
				err := setupSafeBrowsing(c, &settings)
				if err != nil {
					return settings, err
				}
			case "safesearch":
				clog.Info("Safe search is enabled")
				settings.SafeSearchEnabled = true
			case "parental":
				err := setupParental(c, &settings)
				if err != nil {
					return settings, err
				}
			case "blocked_ttl":
				if !c.NextArg() {
					return settings, c.ArgErr()
				}
				blockedTTL, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return settings, c.ArgErr()
				}
				clog.Infof("Blocked request TTL is %d", blockedTTL)
				settings.BlockedTTL = uint32(blockedTTL)
			case "filter":
				if !c.NextArg() || len(c.Val()) == 0 {
					return settings, c.ArgErr()
				}

				// Initialize filter and add it to the list
				path := c.Val()
				settings.FilterPaths = append(settings.FilterPaths, path)
				clog.Infof("Added filter list %s", path)

				err := setupUpdateInfo(path, &settings, c)
				if err != nil {
					clog.Errorf("Failed to setup update info: %v", err)
					return settings, c.ArgErr()
				}
			}
		}
	}

	sort.Strings(settings.FilterPaths)
	settings.filterPathsKey = strings.Join(settings.FilterPaths, "#")

	return settings, nil
}

// defaultPluginSettings -- settings to use if nothing is configured
var defaultPluginSettings = plugSettings{
	SafeSearchEnabled:      false,
	SafeBrowsingEnabled:    false,
	SafeBrowsingBlockHost:  "standard-block.dns.adguard.com",
	SafeBrowsingFilterPath: "",
	ParentalEnabled:        false,
	ParentalBlockHost:      "family-block.dns.adguard.com",
	ParentalFilterPath:     "",
	BlockedTTL:             3600, // in seconds
	FilterPaths:            make([]string, 0),
	Update:                 map[string]*updateInfo{},
}

// setupUpdateInfo configures updateInfo for the specified filter list
func setupUpdateInfo(path string, settings *plugSettings, c *caddy.Controller) error {
	u := &updateInfo{
		path:            path,
		ttl:             1 * time.Hour,
		lastTimeUpdated: time.Now(),
	}

	if c.NextArg() && len(c.Val()) > 0 {
		u.url = c.Val()
		clog.Infof("%s update URL is %s", path, u.url)
	}

	if c.NextArg() && len(c.Val()) > 0 {
		ttl, err := strconv.Atoi(c.Val())
		if err != nil || ttl <= 0 {
			return c.ArgErr()
		}
		clog.Infof("%s filter list TTL is %d seconds", path, ttl)
		u.ttl = time.Duration(ttl) * time.Second
	}

	if _, found := settings.Update[u.path]; !found && u.url != "" {
		settings.Update[u.path] = u
	}

	return nil
}

// setupSafeBrowsing loads safebrowsing settings
func setupSafeBrowsing(c *caddy.Controller, settings *plugSettings) error {
	clog.Info("SafeBrowsing is enabled")
	settings.SafeBrowsingEnabled = true

	if !c.NextArg() || len(c.Val()) == 0 {
		clog.Info("SafeBrowsing filter list is not configured")
		return c.ArgErr()
	}
	settings.SafeBrowsingFilterPath = c.Val()
	clog.Infof("SafeBrowsing filter list is set to %s", settings.SafeBrowsingFilterPath)

	if c.NextArg() && len(c.Val()) > 0 {
		settings.SafeBrowsingBlockHost = c.Val()
		clog.Infof("SafeBrowsing block host is set to %s", settings.SafeBrowsingBlockHost)
	}

	return setupUpdateInfo(settings.SafeBrowsingFilterPath, settings, c)
}

// setupParental loads parental control settings
func setupParental(c *caddy.Controller, settings *plugSettings) error {
	clog.Info("Parental control is enabled")
	settings.ParentalEnabled = true

	if !c.NextArg() || len(c.Val()) == 0 {
		clog.Info("Parental control filter list is not configured")
		return c.ArgErr()
	}
	settings.ParentalFilterPath = c.Val()
	clog.Infof("Parental control filter list is set to %s", settings.ParentalFilterPath)

	if c.NextArg() && len(c.Val()) > 0 {
		settings.ParentalBlockHost = c.Val()
		clog.Infof("Parental control block host is set to %s", settings.ParentalBlockHost)
	}

	return setupUpdateInfo(settings.ParentalFilterPath, settings, c)
}

// newDNSEngine initializes a DNS engine using a list of specified filters
// it returns the DNS engine, and the number of lines in the filter files
func newDNSEngine(paths []string) (*urlfilter.DNSEngine, int, error) {
	var lists []filterlist.RuleList
	linesCount := 0

	for i, path := range paths {
		b, err := ioutil.ReadFile(path)
		if err != nil {
			return nil, 0, errorx.Decorate(err, "cannot read from %s", path)
		}
		linesCount += bytes.Count(b, []byte{'\n'})
		if linesCount == 0 {
			return nil, 0, fmt.Errorf("empty file %s", path)
		}

		list := &filterlist.StringRuleList{
			ID:             i,
			RulesText:      string(b),
			IgnoreCosmetic: true,
		}
		lists = append(lists, list)
	}

	storage, err := filterlist.NewRuleStorage(lists)
	if err != nil {
		return nil, 0, errorx.Decorate(err, "cannot create rule storage")
	}

	return urlfilter.NewDNSEngine(storage), linesCount, nil
}

func createSecurityServiceEngine(filename string) (*engineInfo, int, error) {
	rules, cnt, err := safeservices.CreateMap(filename)
	if err != nil {
		return nil, 0, err
	}
	e := &engineInfo{
		filtersPaths: []string{filename},
		data:         rules,
	}
	return e, cnt, nil
}

// initEnginesMap initializes urlfilter filtering engines using the settings
// loaded from the plugin configuration
func initEnginesMap(settings plugSettings) error {
	if settings.SafeBrowsingEnabled {
		if !engineExists(settings.SafeBrowsingFilterPath) {
			clog.Infof("Initializing SafeBrowsing filtering engine for %s", settings.SafeBrowsingFilterPath)
			engine, cnt, err := createSecurityServiceEngine(settings.SafeBrowsingFilterPath)
			if err != nil {
				return errorx.Decorate(err, "cannot create safebrowsing DNS engine")
			}
			enginesMap[settings.SafeBrowsingFilterPath] = engine
			engineStatus.WithLabelValues(settings.SafeBrowsingFilterPath).Set(float64(1))
			engineSize.WithLabelValues(settings.SafeBrowsingFilterPath).Set(float64(cnt))
			engineTimestamp.WithLabelValues(settings.SafeBrowsingFilterPath).SetToCurrentTime()
			clog.Infof("Finished initializing SafeBrowsing filtering engine")
		}
	}

	if settings.ParentalEnabled {
		if !engineExists(settings.ParentalFilterPath) {
			clog.Infof("Initializing Parental filtering engine for %s", settings.ParentalFilterPath)
			engine, cnt, err := createSecurityServiceEngine(settings.ParentalFilterPath)
			if err != nil {
				return errorx.Decorate(err, "cannot create parental control DNS engine")
			}
			enginesMap[settings.ParentalFilterPath] = engine
			engineStatus.WithLabelValues(settings.ParentalFilterPath).Set(float64(1))
			engineSize.WithLabelValues(settings.ParentalFilterPath).Set(float64(cnt))
			engineTimestamp.WithLabelValues(settings.ParentalFilterPath).SetToCurrentTime()
			clog.Infof("Finished initializing Parental filtering engine")
		}
	}

	if !engineExists(settings.filterPathsKey) {
		clog.Infof("Initializing blocking filtering engine for %s", settings.filterPathsKey)
		engine, cnt, err := newDNSEngine(settings.FilterPaths)
		if err != nil {
			return errorx.Decorate(err, "cannot create blocking DNS engine")
		}
		enginesMap[settings.filterPathsKey] = &engineInfo{
			dnsEngine:    engine,
			filtersPaths: settings.FilterPaths,
		}
		engineStatus.WithLabelValues(settings.filterPathsKey).Set(float64(1))
		engineSize.WithLabelValues(settings.filterPathsKey).Set(float64(cnt))
		engineTimestamp.WithLabelValues(settings.filterPathsKey).SetToCurrentTime()
		clog.Infof("Finished initializing blocking filtering engine")
	}
	return nil
}

// initUpdatesMap initializes the "updateMap" which is used for periodic updates check
func initUpdatesMap(settings plugSettings) error {
	if len(settings.Update) == 0 {
		// Do nothing if there are no registered updaters
		return nil
	}

	updatesMapGuard.Lock()
	defer updatesMapGuard.Unlock()

	// Go through the list of updateInfo objects
	// Check if the file exists. If not, download
	for _, u := range settings.Update {
		if _, ok := updatesMap[u.path]; !ok {
			// Add to the map if it's not already there
			updatesMap[u.path] = u

			// Try to do the initial update (for the case when the file does not exist)
			_, err := u.update()
			if err != nil {
				return err
			}
		}
	}

	return nil
}
