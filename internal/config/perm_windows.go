//go:build windows

package config

// checkPerm is a no-op on Windows (ACLs, not mode bits).
func checkPerm(string) error { return nil }
