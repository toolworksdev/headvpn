package secret

// SetTestHooks lets tests in other packages replace the environment lookup.
// It is not part of the supported API.
func SetTestHooks(r *Resolver, getenv func(string) string) {
	r.getenv = getenv
}
