package filterindex

// Homoglyph contains domains that must be protected by the homoglyph filter,
// exceptions, etc.
type Homoglyph struct {
	// Domains contains the data about domain names protected by the homoglyph
	// filter.
	Domains []*HomoglyphProtectedDomain

	// Exceptions contains the data about exceptions to the homoglyph filter.
	Exceptions []*HomoglyphException
}

// HomoglyphProtectedDomain is a single domain protected by the homoglyph
// filter.
type HomoglyphProtectedDomain struct {
	// Domain is the protected domain name, for example "google.com".  It must
	// not be empty and the value must be a valid domain name.  It should be a
	// lowercase eTLD+1 domain.
	Domain string
}

// HomoglyphException is a single exception to the homoglyph filter.  For
// example, if [Homoglyph.Domains] contains "google.com", an exception might be
// "gооgle.com", where the "o" letters are Cyrillic.
type HomoglyphException struct {
	// Domain is the domain name that is skipped by the homoglyph filter.  It
	// must not be empty and the value must be a valid domain name.  It should
	// be a lowercase eTLD+1 domain.
	Domain string
}
