package cmd

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/agd"
	"github.com/AdguardTeam/AdGuardDNS/internal/filter"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/stringutil"
)

// Filtering Groups Configuration

// filteringGroup represents a set of filtering settings.
type filteringGroup struct {
	// RuleLists are the filtering rule lists settings for this filtering group.
	RuleLists *fltGrpRuleLists `yaml:"rule_lists"`

	// Parental are the parental protection settings for this filtering group.
	Parental *fltGrpParental `yaml:"parental"`

	// SafeBrowsing are the general safe browsing settings for this filtering
	// group.
	SafeBrowsing *fltGrpSafeBrowsing `yaml:"safe_browsing"`

	// ID is a filtering group ID.  Must be unique.
	ID string `yaml:"id"`

	// BlockPrivateRelay shows if Apple Private Relay queries are blocked for
	// requests using this filtering group.
	BlockPrivateRelay bool `yaml:"block_private_relay"`

	// BlockFirefoxCanary shows if Firefox canary domain is blocked for
	// requests using this filtering group.
	BlockFirefoxCanary bool `yaml:"block_firefox_canary"`
}

// fltGrpRuleLists contains filter rule lists configuration for a filtering
// group.
type fltGrpRuleLists struct {
	// IDs is a list of filtering rule list IDs used in this group.
	IDs []string `yaml:"ids"`

	// Enabled shows if rule-list based filtering should be enforced.  If it is
	// false, the rest of the settings are ignored.
	Enabled bool `yaml:"enabled"`
}

// fltGrpParental contains parental protection configuration for a filtering
// group.
type fltGrpParental struct {
	// Enabled shows if any kind of parental protection filtering should be
	// enforced at all.  If it is false, the rest of the settings are ignored.
	Enabled bool `yaml:"enabled"`

	// BlockAdult tells if the blocking of adult content using the safe browsing
	// filter should be enforced.
	BlockAdult bool `yaml:"block_adult"`

	// GeneralSafeSearch shows whether the general safe search filtering should
	// be enforced.
	GeneralSafeSearch bool `yaml:"general_safe_search"`

	// YoutubeSafeSearch shows whether the YouTube safe search filtering should
	// be enforced.
	YoutubeSafeSearch bool `yaml:"youtube_safe_search"`
}

// fltGrpSafeBrowsing contains general safe browsing configuration for
// a filtering group.
type fltGrpSafeBrowsing struct {
	// Enabled shows if the general safe browsing filtering should be enforced.
	Enabled bool `yaml:"enabled"`
}

// validate returns an error if the filtering group is invalid.
func (g *filteringGroup) validate() (err error) {
	switch {
	case g == nil:
		return errNilConfig
	case g.RuleLists == nil:
		return errors.Error("no rule_lists")
	case g.ID == "":
		return errors.Error("no id")
	case g.Parental == nil:
		return errors.Error("no parental")
	}

	fltIDs := stringutil.NewSet()
	for i, fltID := range g.RuleLists.IDs {
		if fltIDs.Has(fltID) {
			return fmt.Errorf("rule_lists: at index %d: duplicate id %q", i, fltID)
		}

		_, err = agd.NewFilterListID(fltID)
		if err != nil {
			return fmt.Errorf("rule_lists: at index %d: %w", i, err)
		}

		fltIDs.Add(fltID)
	}

	return nil
}

// filteringGroups are the filtering settings.  A valid instance of
// filteringGroups has no nil items.
type filteringGroups []*filteringGroup

// toInternal converts groups to the filtering groups for the DNS server.
// groups are assumed to be valid.
func (groups filteringGroups) toInternal(
	s filter.Storage,
) (fltGrps map[agd.FilteringGroupID]*agd.FilteringGroup, err error) {
	fltGrps = make(map[agd.FilteringGroupID]*agd.FilteringGroup, len(groups))
	for _, g := range groups {
		filterIDs := make([]agd.FilterListID, len(g.RuleLists.IDs))
		for i, fltID := range g.RuleLists.IDs {
			// Assume that these have already been validated in
			// filteringGroup.validate.
			id := agd.FilterListID(fltID)
			if !s.HasListID(id) {
				return nil, fmt.Errorf("filter list id %q is not in the index", id)
			}

			filterIDs[i] = agd.FilterListID(fltID)
		}

		id := agd.FilteringGroupID(g.ID)
		fltGrps[id] = &agd.FilteringGroup{
			ID:                  id,
			RuleListsEnabled:    g.RuleLists.Enabled,
			RuleListIDs:         filterIDs,
			ParentalEnabled:     g.Parental.Enabled,
			BlockAdult:          g.Parental.BlockAdult,
			SafeBrowsingEnabled: g.SafeBrowsing.Enabled,
			GeneralSafeSearch:   g.Parental.GeneralSafeSearch,
			YoutubeSafeSearch:   g.Parental.YoutubeSafeSearch,
			BlockPrivateRelay:   g.BlockPrivateRelay,
			BlockFirefoxCanary:  g.BlockFirefoxCanary,
		}
	}

	return fltGrps, nil
}

// validate returns an error if these filtering groups are invalid.
func (groups filteringGroups) validate() (err error) {
	if len(groups) == 0 {
		return errors.Error("no filtering_groups")
	}

	ids := stringutil.NewSet()
	for i, g := range groups {
		err = g.validate()
		if err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}

		if ids.Has(string(g.ID)) {
			return fmt.Errorf("at index %d: duplicate id %q", i, g.ID)
		}

		ids.Add(g.ID)
	}

	return nil
}
