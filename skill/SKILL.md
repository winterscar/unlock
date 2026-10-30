---
name: unlock
description: Use when a task needs an authenticated API whose credentials are in 1Password (e.g. OpenTele / OTH, doccla-*.oth.io), when the user says they have unlocked a service or mentions `unlock`, or when a response body starts with "unlock:".
---

# unlock

Credentials never pass through you. The user runs `unlock <service>` in their own terminal. It reads the secret from 1Password (Touch ID) and serves a local proxy that adds auth to your requests until a timer runs out.

**Never run `op` or read 1Password yourself, even if the user offers.** That puts the secret in your context and transcript, which is what `unlock` exists to prevent. Ask for an unlock instead.

## Using a service

1. Check for a live session: `ls ~/.local/state/unlock/`. Each `<service>.json` has `base-url`, `token`, `upstream` and `expires-at`, and only exists while the service is unlocked.
2. No file, or the time has passed? Ask the user to run `unlock <service> [host] [--for 30m]`. The services, their allowed and blocked hosts, and their path rules are in `/etc/unlock/services.json`. It's safe to read: it holds `op://` references only, never secrets.
3. Send requests to `base-url`, not the real host, with the session token and no `Authorization` header:

```bash
f=~/.local/state/unlock/opentele.json
curl -s -H "X-Unlock-Token: $(jq -r .token $f)" -H 'Accept: application/json' \
  "$(jq -r '."base-url"' $f)/clinician/api/patientgroups"
```

Read the token inline like this. Never echo it or paste it into output.

A session covers one host, the `upstream` in the state file. For a different host, ask the user to unlock that host. If `expires-at` will pass before a long task finishes, say so up front.

## Responses from the proxy

The proxy's own errors are plain text starting `unlock:`. Anything else came from the upstream: handle it as a normal API response.

| Response | Meaning | Do |
|---|---|---|
| 401 "missing or wrong X-Unlock-Token" | Stale token; each unlock issues a new one | Re-read the state file |
| Connection refused | The session expired or was locked | Ask the user to unlock again |
| 403 "… is not allowed for this service" | A path rule blocks it | Tell the user; don't look for another route |
| 502 "login … failed" or "token request … failed; not retrying" | The 1Password item's credentials were rejected | Stop. Ask the user to fix the item, then Ctrl-C and rerun `unlock`. Retrying elsewhere risks locking the account |

## Blocked hosts are deliberate

Some hosts are blocked on purpose (e.g. `doccla-prod.oth.io`). If the user asks for one, say it's blocked by their config and stop. Don't edit the config, don't call the host directly, and don't use other credentials.

## Data

The proxy adds credentials. It does not filter what comes back. Prefer endpoints that don't return patient-identifiable data (root documents, `…/me`, config, counts), and summarise rather than dump anything patient-level.

## Adding a service

That's the user's change, made in `~/nix/modules/unlock.nix`. The auth types and options are documented in `~/src/unlock/README.md`.
