# unlock

Give an agent time-boxed use of one service's credentials from 1Password,
without giving it the credentials.

```
$ unlock opentele doccla-dev.oth.io --for 30m
Unlocked opentele -> https://doccla-dev.oth.io
  proxy:   http://127.0.0.1:51234
  header:  X-Unlock-Token (in ~/.local/state/unlock/opentele.json)
  expires: 2026-10-19T14:30:00Z  (Ctrl-C to lock now)

2026-10-19T14:00:12Z GET /clinician/api/patients -> 200 143ms
```

You run it in your own terminal. It reads the service's credentials with
`op read`, so 1Password asks for Touch ID, and keeps them only in memory. The
agent gets a local proxy URL and a session token that is worthless anywhere
else. The proxy adds the real credential to each request and forwards it to
the one host you unlocked. When the time runs out, or you press Ctrl-C, the
process exits and the credential is gone. Every request is printed as it
happens.

## How the agent uses it

Read `~/.local/state/unlock/<service>.json` for `base-url` and `token`, then
send requests to `base-url` with an `X-Unlock-Token: <token>` header and no
`Authorization` header. The file exists only while the service is unlocked.
A snippet for `CLAUDE.md`:

```markdown
## Service credentials
Never read credentials yourself (no `op`, no 1Password). If you need a service,
ask me to run `unlock <service>`. While it is unlocked,
~/.local/state/unlock/<service>.json holds `base-url` and `token`. Send requests
to base-url with header `X-Unlock-Token: <token>`; the proxy adds auth.
```

## What it guarantees, and what it does not

The design assumes the agent has a shell running as you.

- **No control surface.** There is no admin API, nothing to approve requests
  through, and no policy that reloads. Settings are fixed when you start it.
- **Root-owned install.** `install.sh` installs the script and its config owned
  by root, and pins the interpreter to an absolute path (a nix store path).
  `unlock` refuses to start if the script, config or `op` binary, or the
  directories holding them, can be written by you. Otherwise an agent could
  edit them to capture the secret the next time you unlock.
- **One host.** Requests only go to the host you unlocked. Redirects are not
  followed. `:deny-hosts` is checked before anything is read from 1Password.
- **Agent headers are not trusted.** It drops any `Authorization`, `Cookie` or
  hop-by-hop headers the agent sends.
- **Browsers are kept out.** It checks the `Host` header so a web page in your
  browser can't use the proxy by pointing a domain at 127.0.0.1 (DNS
  rebinding). The session token, a custom header, also stops cross-site
  requests from web pages.
- **Echoes are scrubbed.** If a credential appears in a response header or
  body, it is replaced before the agent sees it.

What is still exposed:

- **The agent can run `op read` itself.** That triggers a Touch ID prompt you
  did not expect, so only approve prompts straight after you typed `unlock`.
- **Response data reaches the agent.** Nothing inspects what the upstream sends
  back. Use `:allow` rules to keep the agent on the paths you mean.
- **Your shell setup is yours to protect.** An agent could add an alias or
  function called `unlock` to your shell rc files. Run `/usr/local/bin/unlock`
  by full path if that worries you.
- **It is not a sandbox.** It stops credentials leaking by accident or through
  casual prompt injection, not a determined attacker already running as you.

## Install

Requirements:

- [babashka](https://babashka.org)
- The 1Password CLI, installed with the official package so `/usr/local/bin/op`
  is root-owned. The Homebrew cask's symlink will be rejected.
- "Integrate with 1Password CLI" turned on in the 1Password app, so `op read`
  asks for Touch ID.

```
./install.sh                                  # needs sudo
sudo -e /usr/local/etc/unlock/services.edn    # point the op:// references at real items
```

Re-run `install.sh` after changing `unlock.clj` or upgrading babashka.

## Configuration

See [`services.example.edn`](services.example.edn). `:auth` types:

- `:bearer`, `:basic` and `:header` inject the secret directly.
- `:oth-client` exchanges an OpenTele system client's key and secret for a
  Bearer token at `<host>/idp2/clients/auth`. It refreshes the token near
  expiry, and once on a 401.

`{host}` in an `op://` reference is replaced with the unlocked host, so each
environment can have its own 1Password item.

## Development

```
bb test
./unlock.clj opentele --config services.example.edn --dry-run --for 1m
```

`--dry-run` runs the whole proxy with 1Password and the upstream mocked: the
response says what would have been sent. It warns about the integrity checks
instead of refusing.
