// Package version contains AdGuardDNS version information.
package version

// These can be set by the linker.  Unfortunately, we cannot set constants
// during linking, and Go doesn't have a concept of immutable variables, so to
// be thorough we have to only export them through getters.
var (
	branch     string
	committime string
	revision   string
	version    string

	name = "AdGuardDNS"
)

// Branch returns the compiled-in value of the Git branch.
func Branch() (b string) {
	return branch
}

// CommitTime returns the compiled-in value of the commit time as a string.
func CommitTime() (t string) {
	return committime
}

// Revision returns the compiled-in value of the Git revision.
func Revision() (r string) {
	return revision
}

// Version returns the compiled-in value of the AdGuardDNS version as a
// string.
func Version() (v string) {
	return version
}

// Name returns the compiled-in value of the AdGuardDNS name.
func Name() (n string) {
	return name
}
