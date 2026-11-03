// Package awsconfig reads the parts of the AWS CLI config file (~/.aws/config)
// that `aws sso login` uses: sso-session sections and the profiles that point
// at them (or carry the legacy sso_start_url themselves).
package awsconfig

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DefaultPath is $AWS_CONFIG_FILE or ~/.aws/config, like the AWS CLI.
func DefaultPath() string {
	if p := os.Getenv("AWS_CONFIG_FILE"); p != "" {
		return p
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".aws", "config")
}

// Target is what a name resolves to.
type Target struct {
	// Name is the name that was asked for.
	Name string
	// Session is the sso-session name, or "" for a legacy profile.
	Session string
	// StartURL and Region come from the session (or the legacy profile).
	StartURL string
	Region   string
	// LoginArgs are the arguments that select this target for `aws sso login`.
	LoginArgs []string
	// Profiles are the profiles that use this login, sorted; the first one
	// is a reasonable profile to verify the login with.
	Profiles []string
}

// File is the parsed config: section name → key → value. Section names are
// kept as written in the brackets ("profile x", "sso-session y", "default").
type File map[string]map[string]string

// Parse reads an INI file as the AWS CLI writes it. Nested sub-sections
// (indented keys under "s3 =") are skipped: nothing here needs them.
func Parse(r io.Reader) (File, error) {
	f := File{}
	var cur map[string]string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1<<20)
	for sc.Scan() {
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.Join(strings.Fields(line[1:len(line)-1]), " ")
			cur = f[name]
			if cur == nil {
				cur = map[string]string{}
				f[name] = cur
			}
			continue
		}
		if cur == nil || raw[0] == ' ' || raw[0] == '\t' {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		cur[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return f, sc.Err()
}

// Load parses the file at path.
func Load(path string) (File, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return Parse(fh)
}

// Resolve finds name as an sso-session first, then as a profile (that names
// an sso_session, or carries a legacy sso_start_url).
func (f File) Resolve(name string) (Target, error) {
	if s, ok := f["sso-session "+name]; ok {
		t := Target{Name: name, Session: name, StartURL: s["sso_start_url"], Region: s["sso_region"],
			LoginArgs: []string{"--sso-session", name}}
		for sec, kv := range f {
			if p, ok := profileName(sec); ok && kv["sso_session"] == name {
				t.Profiles = append(t.Profiles, p)
			}
		}
		sort.Strings(t.Profiles)
		return t, t.check()
	}
	sec := "profile " + name
	if name == "default" {
		sec = "default"
	}
	p, ok := f[sec]
	if !ok {
		return Target{}, fmt.Errorf("%q is neither an [sso-session] nor a [profile] in the AWS config", name)
	}
	if s := p["sso_session"]; s != "" {
		t, err := f.Resolve(s)
		if err != nil {
			return Target{}, fmt.Errorf("profile %q: %w", name, err)
		}
		t.Name = name
		// Verify with the profile that was named, not just any of the session's.
		t.Profiles = append([]string{name}, without(t.Profiles, name)...)
		return t, nil
	}
	if p["sso_start_url"] == "" {
		return Target{}, fmt.Errorf("profile %q does not use IAM Identity Center (no sso_session or sso_start_url)", name)
	}
	t := Target{Name: name, StartURL: p["sso_start_url"], Region: p["sso_region"],
		LoginArgs: []string{"--profile", name}, Profiles: []string{name}}
	return t, t.check()
}

func (t Target) check() error {
	if t.StartURL == "" || t.Region == "" {
		return fmt.Errorf("%q needs sso_start_url and sso_region", t.Name)
	}
	return nil
}

func profileName(section string) (string, bool) {
	if section == "default" {
		return "default", true
	}
	return strings.CutPrefix(section, "profile ")
}

func without(list []string, s string) []string {
	var out []string
	for _, v := range list {
		if v != s {
			out = append(out, v)
		}
	}
	return out
}
