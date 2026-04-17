// Package dnsservertest provides convenient helper functions for unit-tests
// in packages related to dnsserver.
package dnsservertest

// DomainName is a common domain name used in tests.
const DomainName = "test.example"

// FQDN is the fully qualified version of [DomainName].
const FQDN = DomainName + "."

// SubdomainName is a common subdomain of a [DomainName] used in tests.
const SubdomainName = "sub.test.example"
