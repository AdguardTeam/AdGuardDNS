package agd

// Versions

// These are set by the linker.  Unfortunately, we cannot set constants during
// linking, and Go doesn't have a concept of immutable variables, so to be
// thorough we have to only export them through getters.
var (
	branch    string
	buildtime string
	revision  string
	version   string
)

// Branch returns the compiled-in value of the Git branch.
func Branch() (b string) {
	return branch
}

// BuildTime returns the compiled-in value of the build time as a string.
func BuildTime() (t string) {
	return buildtime
}

// Revision returns the compiled-in value of the Git revision.
func Revision() (r string) {
	return revision
}

// Version returns the compiled-in value of the AdGuard DNS version as a string.
func Version() (v string) {
	return version
}
