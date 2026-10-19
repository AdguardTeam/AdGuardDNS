package agd

import "net/netip"

// AccountIPConfig is the configuration of the account's IP addresses.
type AccountIPConfig struct {
	// IPs are the configurations for each account IP address.  All items must
	// not be nil and must be valid.
	IPs []*AccountIP

	// Enabled shows if the account IPs feature is enabled.
	Enabled bool
}

// AccountIP is the configuration of the single account IP address.
type AccountIP struct {
	// Address is the configured account IP address.  It must be valid.
	Address netip.Addr

	// Domains are the configurations for each custom domain for this account IP
	// address.  All items must not be nil and must be valid.
	Domains []*CustomDomainConfig

	// Enabled shows if this account IP address is enabled.
	Enabled bool
}
