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
- **Root-owned install.** The nix module puts the script and its config in the
  nix store, which nothing can edit, and the script's interpreter is a store
  path too. `unlock` refuses to start if the script, config or `op` binary,
  or the directories holding them, can be written by you. Otherwise an agent
  could edit them to capture the secret the next time you unlock.
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
- **Your shell setup is yours to protect.** The module defines `unlock` as an
  alias in `/etc/zprofile` (root-owned), so a fake `unlock` earlier on `PATH`
  doesn't win. An agent could still override it from your own rc files, or
  replace the `~/.zshrc` symlink.
- **It is not a sandbox.** It stops credentials leaking by accident or through
  casual prompt injection, not a determined attacker already running as you.

## Install (nix-darwin)

The flake exports `darwinModules.default`:

```nix
# flake.nix inputs
unlock = { url = "git+ssh://git@github.com/winterscar/unlock.git"; inputs.nixpkgs.follows = "nixpkgs"; };

# a darwin module
{ unlock, ... }: {
  imports = [ unlock.darwinModules.default ];
  programs.unlock = {
    enable = true;
    services.opentele = {
      allow-hosts = [ "*.oth.io" ];
      deny-hosts = [ "doccla-prod.oth.io" ];
      default-host = "doccla-dev.oth.io";
      auth = {
        type = "login";
        login-path = "/idp2/users/auth";
        username = "op://Employee/OTH - Dev/username";
        password = "op://Employee/OTH - Dev/password";
      };
    };
  };
}
```

Enabling it:

- Turns on nix-darwin's `programs._1password`, which installs the 1Password
  CLI root-owned at `/usr/local/bin/op`, where the 1Password app's CLI
  integration needs it.
- Writes the services to `/etc/unlock/services.json`.
- Adds `unlock` to the system packages.

The 1Password app itself isn't managed by the module. In its settings, turn on
Developer > "Integrate with 1Password CLI" so `op read` asks for Touch ID.

After changing `unlock.clj`, commit and run `nix flake update unlock` in the
system flake.

## Configuration

See [`services.example.edn`](services.example.edn). In nix, keywords become
strings: `type = "login"`, `allow = [ [ "get" "/api/**" ] ]`. `:auth`
types:

- `:bearer`, `:basic` and `:header` inject the secret directly.
- `:login` sends Basic `username:password` to `:login-path` and uses the
  token in the JSON response (`:token-field`, default `token`; a dotted path
  like `data.access` works) as a Bearer token. It logs in again when
  `:exp-field` (default `exp`, unix seconds) is close, and once if a request
  gets a 401. A failed login is not retried until you restart `unlock`,
  because many services lock an account after repeated bad logins.
- `:client-credentials` does an OAuth2 client credentials grant: it POSTs
  `client_id` and `client_secret` (plus `:scope` and `:expires-in`, if set)
  form-encoded to `:token-path` and sends the returned `access_token` as a
  Bearer token. It fetches a new one when `expires_in` is nearly up, and once
  if a request gets a 401. As with `:login`, a failed request is not retried.

`{host}` in an `op://` reference is replaced with the unlocked host, so each
environment can have its own 1Password item.

## Development

```
bb test                 # or: nix flake check
./unlock.clj opentele --config services.example.edn --dry-run --for 1m
```

`--dry-run` runs the whole proxy with 1Password and the upstream mocked: the
response says what would have been sent. It warns about the integrity checks
instead of refusing.

## Claude skill

[`skill/SKILL.md`](skill/SKILL.md) teaches Claude Code the workflow: check for
a live session, never read 1Password itself, read the proxy's errors, and
treat blocked hosts as deliberate. Link the `skill` directory to
`~/.claude/skills/unlock`, e.g. with home-manager:

```nix
home-manager.users.<you>.home.file.".claude/skills/unlock".source = "${unlock}/skill";
```
