package agd

import (
	"fmt"
)

// Common Errors

// ArgumentError is returned by functions when a value of an argument is
// invalid.
type ArgumentError struct {
	// Name is the name of the argument.
	Name string

	// Message is an optional additional message.
	Message string
}

// Error implements the error interface for *ArgumentError.
func (err *ArgumentError) Error() (msg string) {
	if err.Message == "" {
		return fmt.Sprintf("argument %s is invalid", err.Name)
	}

	return fmt.Sprintf("argument %s is invalid: %s", err.Name, err.Message)
}

// EntityName is the type for names of entities.  Currently only used in errors.
type EntityName string

// Current entity names.
const (
	EntityNameDevice  EntityName = "device"
	EntityNameProfile EntityName = "profile"
)

// NotFoundError is an error returned by lookup methods when an entity wasn't
// found.
//
// We use separate types that implement a common interface instead of a single
// structure to reduce allocations.
type NotFoundError interface {
	error

	// EntityName returns the name of the entity that couldn't be found.
	EntityName() (e EntityName)
}

// DeviceNotFoundError is a NotFoundError returned by lookup methods when
// a device wasn't found.
type DeviceNotFoundError struct{}

// type check
var _ NotFoundError = DeviceNotFoundError{}

// Error implements the NotFoundError interface for DeviceNotFoundError.
func (DeviceNotFoundError) Error() (msg string) { return "device not found" }

// EntityName implements the NotFoundError interface for DeviceNotFoundError.
func (DeviceNotFoundError) EntityName() (e EntityName) { return EntityNameDevice }

// ProfileNotFoundError is a NotFoundError returned by lookup methods when
// a profile wasn't found.
type ProfileNotFoundError struct{}

// type check
var _ NotFoundError = ProfileNotFoundError{}

// Error implements the NotFoundError interface for ProfileNotFoundError.
func (ProfileNotFoundError) Error() (msg string) { return "profile not found" }

// EntityName implements the NotFoundError interface for ProfileNotFoundError.
func (ProfileNotFoundError) EntityName() (e EntityName) { return EntityNameProfile }

// NotACountryError is returned from NewCountry when the string doesn't represent
// a valid country.
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
