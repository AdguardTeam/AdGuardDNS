package tlsconfig

import (
	"fmt"
	"os"
	"strings"

	"github.com/AdguardTeam/golibs/validate"
	"github.com/prometheus/common/model"
)

// SessionTicketLen is the length of a single TLS session ticket key in bytes.
//
// NOTE: Unlike Nginx, Go's crypto/tls doesn't use the random bytes from the
// session ticket keys as-is, but instead hashes these bytes and uses the first
// 48 bytes of the hashed data as the key name, the AES key, and the HMAC key.
const SessionTicketLen = 32

// SessionTicket is a type alias for a single TLS session ticket.
type SessionTicket = [SessionTicketLen]byte

// NewSessionTicket returns a new TLS session ticket from the provided data, if
// it contains at least [SessionTicketLen] bytes.
func NewSessionTicket(data []byte) (ticket SessionTicket, err error) {
	// TODO(a.garipov):  Add validate.Len.
	err = validate.NoLessThan("length", len(data), SessionTicketLen)
	if err != nil {
		return SessionTicket{}, err
	}

	return SessionTicket(data), nil
}

// SessionTicketName is a type for the name of a TLS session ticket.  A valid
// SessionTicketName may be used as a file name as well as metrics label.
type SessionTicketName string

// NewSessionTicketName creates a new session ticket name.  It returns an error
// if the provided name is not valid.
func NewSessionTicketName(str string) (name SessionTicketName, err error) {
	err = validate.NotEmpty("str", str)
	if err != nil {
		return "", err
	}

	if i := strings.IndexRune(str, os.PathSeparator); i >= 0 {
		return "", fmt.Errorf("str: at index %d: bad rune %q", i, os.PathSeparator)
	}

	// TODO(e.burkov):  Perhaps, the metrics interface should have a method to
	// check strings for valid label values instead of bounding it to the
	// Prometheus-based implementation.
	if !model.LabelValue(str).IsValid() {
		return "", fmt.Errorf("str: not a valid label value: %q", str)
	}

	return SessionTicketName(str), nil
}

// NamedTickets is a set of TLS session tickets mapped to their names.
type NamedTickets = map[SessionTicketName]SessionTicket
