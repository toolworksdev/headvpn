package totp

import (
	"encoding/base32"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 column (8 digits).
func TestRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	cases := []struct {
		unix int64
		want string
	}{
		{59, "94287082"},
		{1111111109, "07081804"},
		{1111111111, "14050471"},
		{1234567890, "89005924"},
		{2000000000, "69279037"},
		{20000000000, "65353130"},
	}
	for _, c := range cases {
		if got := At(key, time.Unix(c.unix, 0), 8); got != c.want {
			t.Errorf("At(%d) = %s, want %s", c.unix, got, c.want)
		}
	}
}

func TestCodeFromBase32WithSpacesAndLowercase(t *testing.T) {
	b32 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))
	messy := "  " + lower(b32[:8]) + " " + b32[8:] + " "
	got, err := Code(messy, time.Unix(59, 0))
	if err != nil {
		t.Fatal(err)
	}
	if got != "287082" {
		t.Fatalf("got %s, want 287082", got)
	}
}

func TestRejectsBadSecrets(t *testing.T) {
	for _, s := range []string{"", "   ", "not-base32!!"} {
		if _, err := Code(s, time.Now()); err == nil {
			t.Errorf("Code(%q) accepted an invalid secret", s)
		}
	}
}

func lower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
