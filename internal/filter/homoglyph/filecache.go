package homoglyph

import (
	"fmt"

	"github.com/AdguardTeam/AdGuardDNS/internal/filter/filterindex"
	"github.com/AdguardTeam/golibs/validate"
)

// indexCacheVersion is the current schema version of the homoglyph-filter index
// cache.
//
// NOTE:  Increment this value on every change in [indexCache] that requires a
// change in the JSON representation.
const indexCacheVersion uint = 1

// indexCache is the data-transfer object for the homoglyph-filter index cache.
type indexCache struct {
	// Domains contains the data about domain names protected by the homoglyph
	// filter.
	Domains []*indexProtectedDomain `json:"domains"`

	// Exceptions contains the data about exceptions to the homoglyph filter.
	Exceptions []*indexException `json:"exceptions"`

	// SchemaVersion is the version of the schema.
	SchemaVersion uint `json:"schema_version"`
}

// indexProtectedDomain is a single protected domain.
type indexProtectedDomain struct {
	// Domain is the protected domain name, for example "google.com".  It must
	// not be empty and the value must be a valid domain name.  It should be a
	// lowercase eTLD+1 domain.
	Domain string `json:"domain"`
}

// indexException is a single exception to the homoglyph filter.  For example,
// if [Homoglyph.Domains] contains "google.com", an exception might be
// "gоogle.com", with Cyrillic "о" instead of Latin "o".
type indexException struct {
	// Domain is the domain name that is skipped by the homoglyph filter.  It
	// must not be empty and the value must be a valid domain name.  It should
	// be a lowercase eTLD+1 domain.
	Domain string `json:"domain"`
}

// newIndexCache converts idx into the data-transfer object for filesystem
// caching.  idx must not be nil.
func newIndexCache(idx *filterindex.Homoglyph) (c *indexCache) {
	domains := make([]*indexProtectedDomain, 0, len(idx.Domains))
	for _, d := range idx.Domains {
		domains = append(domains, &indexProtectedDomain{
			Domain: d.Domain,
		})
	}

	exceptions := make([]*indexException, 0, len(idx.Exceptions))
	for _, e := range idx.Exceptions {
		exceptions = append(exceptions, &indexException{
			Domain: e.Domain,
		})
	}

	return &indexCache{
		Domains:       domains,
		Exceptions:    exceptions,
		SchemaVersion: indexCacheVersion,
	}
}

// toInternal converts the index cache from JSON into internal structures.  c
// must be valid.
func (c *indexCache) toInternal() (idx *filterindex.Homoglyph, err error) {
	err = validate.InRange("schema_version", c.SchemaVersion, indexCacheVersion, indexCacheVersion)
	if err != nil {
		return nil, fmt.Errorf("malformed cache: %w", err)
	}

	domains := make([]*filterindex.HomoglyphProtectedDomain, 0, len(c.Domains))
	for _, d := range c.Domains {
		domains = append(domains, &filterindex.HomoglyphProtectedDomain{
			Domain: d.Domain,
		})
	}

	exceptions := make([]*filterindex.HomoglyphException, 0, len(c.Exceptions))
	for _, e := range c.Exceptions {
		exceptions = append(exceptions, &filterindex.HomoglyphException{
			Domain: e.Domain,
		})
	}

	return &filterindex.Homoglyph{
		Domains:    domains,
		Exceptions: exceptions,
	}, nil
}
