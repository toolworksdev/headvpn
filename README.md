# headvpn

Connect a corporate VPN behind single sign-on **without a human at the
browser**, so scripts and AI agents (Claude Code, OpenClaw, cron jobs…) can
bring it up and down on demand. VPN clients and identity providers are
pluggable; *What works today* lists the ones implemented.

```console
$ headvpn connect work --json
{"profile":"work","state":"Connected"}
$ headvpn disconnect work
work	NotConnected
```

Status: **early**. Validated end to end on real setups listed in *What works
today*; read it before relying on it.

## Why

AWS Client VPN with SAML federation is built for a person: the client opens a
browser, you type a password and a one-time code, and the IdP posts the SAML
assertion back to the client on `127.0.0.1:35001`. That is fine on a laptop
and useless for an agent that has to reach an internal service at 3 a.m.

`headvpn` answers that one step for you. The tunnel, routes and DNS stay in
the hands of the **official AWS VPN Client**; this tool only logs in to the
IdP over plain HTTP and hands the assertion to the client's local consumer.

## What works today

| Piece | State |
|---|---|
| Backend `aws-official`: AWS VPN Client **6.x CLI on macOS** | implemented |
| IdP `keycloak`: username + password + TOTP (or a typed code) | implemented |
| Backend `aws-openvpn`: the OpenVPN shipped with AWS VPN Client **5.x for Linux** | implemented |
| Backend `pritunl`: the official Pritunl client CLI (macOS, Linux) | implemented |
| IdP `entra`: Microsoft Entra ID, password + TOTP (with `pritunl`) | implemented |
| Secrets in the macOS Keychain / Linux Secret Service / `env:` / `cmd:` | implemented |
| Windows | not yet (see *Roadmap*) |
| Okta | not yet |

### Which IdPs can work

Capturing the login URL, delivering the assertion and confirming the tunnel
do not depend on the IdP. The login itself does: each IdP needs an adapter
that answers its pages over plain HTTP. Keycloak and Entra ID are
implemented; the rest is an estimate.

| IdP | Unattended login | Why |
|---|---|---|
| Keycloak (username + password + TOTP) | **yes — implemented** | plain HTML forms |
| Other form-based IdPs (Authentik, ADFS forms, Shibboleth) | likely | same pattern as Keycloak, needs an adapter |
| Okta | only with a TOTP factor | has an authentication API; push needs a person |
| Microsoft Entra ID (password + TOTP) | **yes — implemented** (with `pritunl`) | needs an authenticator-app code as second factor; push, number matching, passkeys or compliant-device policies need a person |
| Google Workspace | unlikely | bot detection and challenges; would need a real automated browser |
| Passkeys, FIDO keys, push approvals (any IdP) | **no** | they exist to require a person |

Any IdP works when the default browser already holds a live session: the
browser completes the login and `headvpn` reports `"via": "browser"`. An agent
cannot count on that.

### How the login URL is found (and its limits)

The AWS VPN Client 6.x CLI does not print the SAML URL and ignores `$BROWSER`;
its daemon only answers callers signed by AWS, and the VPN server rejects an
assertion issued for any request other than the client's own. What the client
does is run `/usr/bin/open <saml-url>`, and that argv is visible for about a
second in the process table of the same user. `headvpn` watches for it
(every 5 ms, only `open` processes of your user whose parent is
`aws-vpn-client`, only URLs under `idp_origin`). No browser data is read and
no extra permission is needed.

Fallback: the history of Chromium-family browsers (Brave, Chrome, Edge, Arc,
Chromium). Under launchd macOS blocks reading it unless the binary has Full
Disk Access.

Side effects you will notice:

- the default browser still receives the URL, so a tab with the IdP page
  appears;
- if that browser holds a live IdP session it completes the login by itself;
  `headvpn` sees the client reach `Connected` and reports `"via": "browser"`
  (otherwise `"via": "headvpn"`).

## Install

Download the archive for your system from
[Releases](https://github.com/toolworksdev/headvpn/releases) (macOS and Linux,
arm64 and amd64), check it, and put `headvpn` on your `PATH`:

```sh
v=0.1.0; f=headvpn_${v}_darwin_arm64.tar.gz
curl -fsSLO https://github.com/toolworksdev/headvpn/releases/download/v$v/$f
curl -fsSLO https://github.com/toolworksdev/headvpn/releases/download/v$v/SHA256SUMS
shasum -a 256 --ignore-missing -c SHA256SUMS      # Linux: sha256sum --ignore-missing -c
gh attestation verify $f --repo toolworksdev/headvpn  # built by this repo's CI, from which commit
tar -xzf $f headvpn && install -m 755 headvpn ~/.local/bin/
```

Every release is built by the `release` workflow from a tag on `main`, and
carries a signed build provenance attestation. The macOS binaries are not
notarized: downloaded with `curl` they run as is; downloaded with a browser,
macOS quarantines them (`xattr -d com.apple.quarantine headvpn`).

Or build it with Go:

```sh
go install github.com/toolworksdev/headvpn/cmd/headvpn@latest
```

Requires the AWS VPN Client 6.x with your profile already imported (the
profile name is what `aws-vpn-client list-profiles` shows).

### Linux

The `aws-openvpn` backend runs `acvc-openvpn`, the OpenVPN build inside
AWS's Linux client package, **unmodified**, and talks to it over its
management interface. The VPN server sends the SAML login URL in its
first challenge, so no browser and no desktop session are needed.

1. Install AWS VPN Client 5.x for Linux from AWS (the `.deb`). Only its
   `/opt/awsvpnclient/Service/Resources/openvpn` directory is used; it must be
   owned by root, which the package does.
2. Export the client profile (`.ovpn`) from the Client VPN endpoint and put it
   somewhere root can read.
3. The tunnel needs root. `headvpn connect` starts its root half with
   `sudo -n`, so either run it as root or allow exactly that, e.g. in
   `/etc/sudoers.d/headvpn`:

   ```
   youruser ALL=(root) NOPASSWD: /usr/local/bin/headvpn __supervise *, /usr/local/bin/headvpn __stop
   ```

   Keep the binary root-owned and not writable by the user.

Secrets **and the profile** are read as the invoking user and handed to the
root process over a pipe (never argv or the environment); the root process
reads no file the caller names, so the sudoers rule cannot be used to make
root read and echo arbitrary files. The root process keeps the session up
and logs in again when the tunnel drops; `headvpn disconnect` ends it.

### Pritunl

The `pritunl` backend drives the official Pritunl client through its CLI
(`pritunl-client`), unmodified, on macOS and Linux. Import the profile in the
client first; `pritunl_profile` is its id or name from `pritunl-client list`.
Requires **pritunl-client 1.4.4777 or newer**: older versions do not report the
single sign-on URL for user profiles (on Linux that version is in Pritunl's
`unstable` repository at the time of writing).

The server keeps an SSO token (`token_ttl` on the server, often 30 days), so
most connects need no login at all (`"via":"token"`). When it asks for one:

- **Without `idp`** — a person finishes the login. `connect` prints
  `{"event":"login_required","login_url":…}` on stderr at once, keeps waiting
  for the tunnel until `connect_timeout`, and exits 4 with `login_url` in the
  result if nobody completed it. The URL works from any browser, a phone
  included, **but only once**: the first visit consumes it. Hand it over
  without a link preview (chat apps fetch links to build previews, and that
  fetch burns it) — e.g. in a code block or between `<` `>`.
- **With `idp = "entra"`** — headvpn signs in to Microsoft Entra ID with the
  password and a TOTP code (`totp_secret`), no person involved. Only the
  "verification code" second factor can be answered: register an authenticator
  app (*Security info → Add method → Authenticator app → I want to use a
  different authenticator app → Can't scan*) to get the base32 key. Push
  approvals, number matching, passkeys and SMS need a person.

The Entra sign-in answers the steps measured on a real tenant: the sign-in
page, the browser-capability check, the verification-code step and "stay
signed in?". Pritunl's Azure SSO returns through `https://auth.pritunl.com`
before reaching the VPN server; that relay is the only extra host the sign-in
follows, and it never receives credentials. Run with `HEADVPN_DEBUG=1` to get
one line per page (host, page id, error code, offered methods — never tokens
or codes) when a tenant shows a step this tool does not answer yet.

```toml
[profiles.office]
backend         = "pritunl"
pritunl_profile = "vpn (ana)"
connect_timeout = "10m"            # how long to wait for a person's login
# idp         = "entra"            # uncomment to sign in without a person
# username    = "ana@example.com"
# password    = "keychain:headvpn/office.password"
# totp_secret = "keychain:headvpn/office.totp"
```

## Configuration

`~/.config/headvpn/config.toml`:

```toml
[profiles.work]
backend      = "aws-official"
aws_profile  = "work"                       # name inside the AWS VPN Client
idp          = "keycloak"
idp_origin   = "https://idp.example.com"    # the ONLY host that gets your password
username     = "ana@example.com"
password     = "keychain:headvpn/work.password"
totp_secret  = "keychain:headvpn/work.totp" # or: otp = "prompt:"
connect_timeout = "2m"
```

On Linux the profile points at the exported `.ovpn` instead:

```toml
[profiles.work]
backend      = "aws-openvpn"
ovpn         = "/etc/headvpn/work.ovpn"     # absolute path, readable by root
idp          = "keycloak"
idp_origin   = "https://idp.example.com"
username     = "ana@example.com"
password     = "keychain:headvpn/work.password"
totp_secret  = "keychain:headvpn/work.totp" # a typed code cannot work: it runs in the background
```

Secret values are **references**, never literals:

| Reference | Source |
|---|---|
| `keychain:<service>/<account>` | macOS Keychain (`security`) or Linux Secret Service (`secret-tool`) |
| `env:NAME` | environment variable |
| `cmd:op read op://vault/item/field` | stdout of a command (1Password, `pass`, Bitwarden…) |
| `prompt:` | asked on the terminal |

Store a secret without it touching your shell history:

```sh
headvpn secret set headvpn/work.password
headvpn secret set headvpn/work.totp
```

The TOTP secret is the base32 **setup key** of your authenticator (Keycloak:
*Signing in → Set up authenticator application → Unable to scan?*), not a
6-digit code.

## Usage and contract for agents

```
headvpn connect <profile>    [--json]
headvpn status [<profile>]   [--json]
headvpn disconnect <profile> [--json]
headvpn profiles
```

| Exit code | Meaning |
|---|---|
| 0 | done (`connect` on an already connected profile is a no-op with `"already": true`) |
| 1 | error |
| 2 | usage |
| 3 | **the IdP rejected the credentials — do not retry automatically** |
| 4 | a person must open `login_url` (pritunl without `idp`); it was not completed in time |

`headvpn` submits the password and the one-time code **once** per run and
never retries a rejection, so a misconfigured agent cannot lock the account.
It also remembers the last TOTP window used per secret (in the user cache
directory): a second run inside the same 30 s waits for the next code instead
of sending one the IdP already accepted, which IdPs reject and count towards
lockout.

**One VPN at a time.** `connect` first disconnects any other configured
profile that is up, and reports it in `switched_from` — e.g. connecting the
AWS profile while Pritunl is up drops Pritunl first, and the other way round.
Two profiles stay up together only when both set `exclusive = false`.
VPNs started outside headvpn (not in the config) are not touched.

**The VPN apps do not need to be open.** Both clients run a background
service (AWS: `com.amazonaws.acvc.osx.core`; Pritunl: `com.pritunl.service` /
`pritunl-client`) that the system keeps alive; `headvpn` talks to it through
the official CLI. Opening the app does not bring a stopped service back
(measured), so when the service is down `headvpn` says so and how an
administrator restarts it.

**When the browser is faster.** On macOS the AWS client also hands the login
URL to the default browser. If that browser still holds an IdP session it
answers first and the client closes its port; `headvpn` then sees the tunnel
coming up and reports `"via":"browser"` instead of failing.

## Running it from an agent that logs in over SSH (macOS)

Over SSH the login keychain is locked for that session: `security` answers
"User interaction is not allowed", so `headvpn connect` cannot read the
password or the TOTP secret. Run `connect` inside the user's GUI session with
a LaunchAgent and trigger it remotely; `status` and `disconnect` do not use
the keychain and work over SSH directly.

`~/Library/LaunchAgents/com.example.headvpn.connect.work.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.headvpn.connect.work</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Users/YOU/.local/bin/headvpn</string>
    <string>connect</string><string>work</string><string>--json</string>
  </array>
  <key>RunAtLoad</key><false/>
  <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/headvpn/connect-work.log</string>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/headvpn/connect-work.log</string>
</dict>
</plist>
```

```sh
# once, on the Mac
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.example.headvpn.connect.work.plist

# from the agent
ssh mac 'launchctl kickstart gui/$(id -u)/com.example.headvpn.connect.work'
ssh mac 'tail -1 ~/Library/Logs/headvpn/connect-work.log'   # {"state":"Connected",...}
ssh mac '~/.local/bin/headvpn disconnect work'
```

The user must be logged in to the GUI session (a locked screen is fine).

## Security model

Read this before you give an agent your VPN.

- **No second human factor.** Storing a TOTP secret next to the password
  turns MFA into "whoever can read both". Prefer a dedicated identity for
  agents where your IdP allows it, scoped by the VPN's authorization rules.
- **Keychain scope (macOS).** Items are read through `/usr/bin/security`, so
  any process running as your user can read them, not only `headvpn`.
- **Credentials only go to `idp_origin`.** The login URL, every form action
  and every redirect are checked against it; anything else aborts before the
  password is sent.
- **The SAML assertion only goes to loopback.** It is a bearer credential; the
  final POST is refused unless its target is `127.0.0.1`/`localhost`.

## Roadmap

- Windows: AWS VPN Client 6.x ships the same CLI as macOS; it needs a way to
  catch the login URL there.
- More IdPs (Entra ID password-only, Okta).

## Development

```sh
go test ./...
```

Tests run against fake IdPs and a fake client; nothing touches a real VPN.

## Credits

The Linux backend (`internal/awsovpn`) derives from *cvpn* by Juan Fajardo ([@w4nch0](https://github.com/w4nch0)),
reused with his permission.

## License

[MIT](LICENSE).
