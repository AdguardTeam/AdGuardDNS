// Package agdpasswd contains authentication utils.
package agdpasswd

import (
	"context"

	"golang.org/x/crypto/bcrypt"
)

// Authenticator represents a password authenticator.
type Authenticator interface {
	// Authenticate returns true if the given passwd is allowed.
	Authenticate(ctx context.Context, passwd []byte) (ok bool)
}

// AllowAuthenticator is an empty authenticator implementation that always
// grants access, regardless of any restrictions.
type AllowAuthenticator struct{}

// type check
var _ Authenticator = AllowAuthenticator{}

// Authenticate implements the [Authenticator] interface for AllowAuthenticator.
func (AllowAuthenticator) Authenticate(_ context.Context, _ []byte) (ok bool) {
	return true
}

// PasswordHashBcrypt is the Bcrypt implementation of [Authenticator].
type PasswordHashBcrypt struct {
	// bytes contains the password hash.
	bytes []byte
}

// NewPasswordHashBcrypt returns a new bcrypt hashed password authenticator.
func NewPasswordHashBcrypt(hashedPassword []byte) (p *PasswordHashBcrypt) {
	return &PasswordHashBcrypt{bytes: hashedPassword}
}

// PasswordHash returns password hash bytes slice.
func (p *PasswordHashBcrypt) PasswordHash() (b []byte) {
	return p.bytes
}

// type check
var _ Authenticator = (*PasswordHashBcrypt)(nil)

// Authenticate implements the [Authenticator] interface for
// *PasswordHashBcrypt.
func (p *PasswordHashBcrypt) Authenticate(_ context.Context, passwd []byte) (ok bool) {
	return bcrypt.CompareHashAndPassword(p.bytes, passwd) == nil
}
