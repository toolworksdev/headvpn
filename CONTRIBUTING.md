# Contributing to headvpn

Thanks for helping. This tool handles VPN credentials, so changes are judged
first on whether they keep secrets where they belong.

## Development

Requirements: Go (the version in `go.mod`).

```sh
go vet ./...
go test -race ./...
gofmt -l .            # must print nothing
```

CI runs the same on macOS, Linux and Windows, plus `staticcheck` and
`govulncheck`. Tests use fake IdPs and a fake VPN client; **never add a test
that talks to a real IdP or VPN endpoint**, and never commit real hostnames,
endpoint IDs, usernames or profiles.

## What a change must keep true

- Credentials are sent only to the configured `idp_origin` (login URL, every
  form action and every redirect are checked).
- The SAML assertion is delivered only to a loopback address.
- The IdP gets one password and one one-time code per run; a rejection is never
  retried automatically.
- Config files hold secret **references**, never values.

If you touch one of these guards, add a test that fails when the guard is
removed, and say in the PR that you checked it (comment the guard out, watch the
test fail, put it back).

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) with a
[gitmoji](https://gitmoji.dev) opening the subject. CI checks every commit of
a pull request **and its title**, because the title becomes the squash commit
on `main`:

```
<type>(<optional scope>)!: <gitmoji> <subject>
```

- `type`: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`,
  `ci`, `chore`, `revert`
- `!` marks a breaking change
- the subject is imperative ("add", not "added")

Examples:

```
feat(idp): ✨ add an Okta adapter for TOTP factors
fix: 🐛 stop the client when the IdP rejects the password
docs: 📝 explain the LaunchAgent setup
ci: 👷 run govulncheck
```

Run the same check locally: `python3 .github/scripts/check_commits.py "$(git log -1 --format=%s)"`.

## Pull requests

- One topic per PR; keep the description in sync with what the diff does.
- `main` is protected: CI must be green and one approval is required.
- New IdP adapters: include the page markup your fake server reproduces (with
  every hostname and token replaced) so reviewers can see what was modelled.

## Reporting a vulnerability

Do not open a public issue. Use GitHub's **Report a vulnerability** (Security
tab → Advisories) so it can be fixed before it is disclosed.
