// Package totp implements RFC 6238 time-based one-time passwords (SHA-1),
// the variant used by Google Authenticator, Keycloak and most IdPs.
package totp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Step is the RFC 6238 default time step.
const Step = 30 * time.Second

// ErrEmptySecret is returned when the secret is empty after normalization.
var ErrEmptySecret = errors.New("totp: empty secret")

// DecodeSecret accepts the base32 key an authenticator setup page shows
// (spaces, lower case and missing padding are tolerated).
func DecodeSecret(s string) ([]byte, error) {
	s = strings.ToUpper(strings.Join(strings.Fields(s), ""))
	s = strings.TrimRight(s, "=")
	if s == "" {
		return nil, ErrEmptySecret
	}
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("totp: secret is not valid base32: %w", err)
	}
	return key, nil
}

// At returns the code for key at time t with the given number of digits.
func At(key []byte, t time.Time, digits int) string {
	counter := uint64(t.Unix()) / uint64(Step/time.Second)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// Code returns the current 6-digit code for a base32 secret.
func Code(secret string, now time.Time) (string, error) {
	key, err := DecodeSecret(secret)
	if err != nil {
		return "", err
	}
	return At(key, now, 6), nil
}
