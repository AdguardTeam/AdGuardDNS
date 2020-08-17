package ratelimit

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"sort"
	"time"

	clog "github.com/coredns/coredns/plugin/pkg/log"
)

func (p *plug) periodicConsulWhitelistReload() {
	ttl := time.Duration(p.consulTTL) * time.Second
	clog.Infof("Reloading consul whitelist every %s", ttl.String())
	ticker := time.NewTicker(ttl)
	defer ticker.Stop()

	// sleep the first time -- we've already loaded the list
	time.Sleep(ttl)

	for t := range ticker.C {
		_ = t // we don't print the ticker time, so assign this `t` variable to underscore `_` to avoid error
		_ = p.reloadConsulWhitelist()
	}
}

func (p *plug) reloadConsulWhitelist() error {
	clog.Infof("Loading consul whitelist from %s", p.consulURL)

	resp, err := http.Get(p.consulURL)
	if err != nil {
		clog.Errorf("Failed to load whitelist: %v", err)
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		clog.Errorf("Failed to read response body: %v", err)
		return err
	}

	var raw []map[string]interface{}
	err = json.Unmarshal(body, &raw)
	if err != nil {
		clog.Errorf("Failed to unmarshal response: %v", err)
		return err
	}

	var whitelist []string
	for _, item := range raw {
		if addr, found := item["Address"]; found {
			if addrStr, ok := addr.(string); ok {
				whitelist = append(whitelist, addrStr)
			}
		}
	}

	if len(whitelist) > 0 {
		sort.Strings(whitelist)
	}
	whitelistLen := len(whitelist) + len(p.whitelist)
	WhitelistCountGauge.Set(float64(whitelistLen))

	clog.Infof("Loaded %d records from %s", len(whitelist), p.consulURL)

	p.consulWhitelistGuard.Lock()
	p.consulWhitelist = whitelist
	p.consulWhitelistGuard.Unlock()

	return nil
}
