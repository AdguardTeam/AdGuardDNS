package profiledb

import "github.com/AdguardTeam/golibs/errors"

// ErrDeviceNotFound is an error returned by lookup methods when a device
// couldn't be found.
const ErrDeviceNotFound errors.Error = "device not found"
