// Package hashprefix defines a storage of hashes of domain names used for
// filtering and serving TXT records with domain-name hashes.
package hashprefix

import "crypto/sha256"

// Hash and hash part length constants.
const (
	// PrefixLen is the length of the hash prefix of the filtered hostname.
	PrefixLen = 2

	// PrefixEncLen is the encoded length of the hash prefix.  Two text
	// bytes per one binary byte.
	PrefixEncLen = PrefixLen * 2

	// hashLen is the length of the whole hash of the checked hostname.
	hashLen = sha256.Size

	// suffixLen is the length of the hash suffix of the filtered hostname.
	suffixLen = hashLen - PrefixLen

	// hashEncLen is the encoded length of the hash.  Two text bytes per one
	// binary byte.
	hashEncLen = hashLen * 2
)

// Prefix is the type of the SHA256 hash prefix used to match against the
// domain-name database.
type Prefix [PrefixLen]byte

// suffix is the type of the rest of a SHA256 hash of the filtered domain names.
type suffix [suffixLen]byte
