package agd

import (
	"io/fs"
	"os"
)

// OS-Related Constants

// DefaultWOFlags is the default set of flags for opening a write-only files.
const DefaultWOFlags = os.O_APPEND | os.O_CREATE | os.O_WRONLY

// DefaultPerm is the default set of permissions for non-executable files.  Be
// strict and allow only reading and writing for the file, and only to the user.
const DefaultPerm fs.FileMode = 0o600

// DefaultDirPerm is the default set of permissions for directories.
const DefaultDirPerm fs.FileMode = 0o700
