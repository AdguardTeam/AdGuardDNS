package geoip

import "fmt"

// NotACountryError is returned from NewCountry when the string doesn't
// represent a valid country.
type NotACountryError struct {
	// Code is the code presented to NewCountry.
	Code string
}

// Error implements the error interface for *NotACountryError.
func (err *NotACountryError) Error() (msg string) {
	return fmt.Sprintf("%q is not a valid iso 3166-1 alpha-2 code", err.Code)
}

// NotAContinentError is returned from NewContinent when the string doesn't
// represent a valid continent.
type NotAContinentError struct {
	// Code is the code presented to NewContinent.
	Code string
}

// Error implements the error interface for *NotAContinentError.
func (err *NotAContinentError) Error() (msg string) {
	return fmt.Sprintf("%q is not a valid continent code", err.Code)
}
