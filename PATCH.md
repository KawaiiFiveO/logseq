# Fork patch: user whitelist for the DB sync server

This fork of [logseq/logseq](https://github.com/logseq/logseq) adds exactly one feature to
`deps/db-sync`: an explicit whitelist of the users allowed to use a self-hosted sync server.
Nothing else is changed. `UPSTREAM_STABLE` records the upstream tag this branch is based on.

## Why

The self-hosted Node adapter validates JWTs against **Logseq's shared Cognito pool**
(`us-east-1_dtagLnju8`), the same pool the hosted service uses. Upstream has no notion of
which accounts may use a given server: `worker/handler/index.cljs` upserts any
successfully-authenticated user into the `users` table and lets them create graphs. Once the
server is reachable, any Logseq account holder who learns the URL can store data on it.

## Configuration

`DB_SYNC_ALLOWED_USERS` — comma or whitespace separated list of Cognito `sub`s,
`cognito:username` values, or verified email addresses. Matching is case-insensitive.

**It fails closed**: unset or blank denies everyone. Prefer `sub`s in production; they are
immutable, whereas an email or username can be changed at the identity provider.

Bootstrapping: you cannot look up your own `sub` while you are locked out, so every denial of
an *authenticated* user is logged at warn as `:db-sync/allowlist-denied` with the `sub`,
`cognito:username` and `email`. Attempt one sync, read the `sub` out of the server log, put it
in the env var, restart.

## What it changes

| File | Change |
| --- | --- |
| `src/logseq/db_sync/worker/allowlist.cljs` | **New.** All of the logic. |
| `src/logseq/db_sync/node/dispatch.cljs` | Existing dispatcher renamed to `dispatch-fetch`; new `handle-node-fetch` gates it. |
| `src/logseq/db_sync/node/server.cljs` | `access-allowed?` also requires the whitelist; `make-env` threads `DB_SYNC_ALLOWED_USERS` through. |
| `src/logseq/db_sync/node/config.cljs` | Reads `DB_SYNC_ALLOWED_USERS` into `:allowed-users`. |
| `test/logseq/db_sync/worker_allowlist_test.cljs` | **New.** Unit tests. |
| `test/logseq/db_sync/test_runner.cljs` | Registers the test namespace. |

Only the Node adapter is gated. The Cloudflare Worker entry point (`worker/dispatch.cljs`) is
untouched — this fork exists to self-host the Node adapter.

## Invariants to preserve when rebasing onto a new upstream tag

1. **Fail closed.** An unset or blank `DB_SYNC_ALLOWED_USERS` must deny everyone. Never add a
   "disable the whitelist" escape hatch — one stray env var would reopen the server to every
   Logseq account on the internet.
2. **Gate every authenticated path, including the WebSocket upgrade.** WS upgrades are handled
   in `node/server.cljs`'s `access-allowed?` and never reach `node/dispatch.cljs`. Patching
   only the HTTP dispatch leaves live sync wide open — this is the easiest mistake to make.
3. **Only `/health`, `OPTIONS` preflight and valid-admin-token requests bypass the gate.**
   See `public-request?`. If upstream adds a new unauthenticated route, decide deliberately.
4. **Keep the logic in `allowlist.cljs`.** The three touched upstream files should contain
   nothing but a call into it, so upstream rewrites of those files stay easy to merge.
5. **An email only counts when `email_verified` is true.** Otherwise an unverified claim could
   impersonate a listed address.

### If upstream restructures the dispatcher

The gate is deliberately shaped so it survives changes to the routing table: it wraps the
whole `cond` rather than living inside it. Take upstream's version of `dispatch-fetch`
wholesale, then re-apply the rename and the wrapper. Do **not** hoist the `OPTIONS` check into
the routing `cond` — upstream handles `/assets/` preflight specially, before the generic
`OPTIONS` branch.

## Behaviour change to expect

Unauthenticated and non-whitelisted API requests return **403** where upstream returns 401.
Upstream's `deps/db-sync/README.md` smoke test documents the 401.
