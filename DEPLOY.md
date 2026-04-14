# Deploy Domain Failover Worker

## 1. Create KV namespace

The worker stores the active and backup lists in KV under two keys: **active** (JSON object) and **backups** (JSON array). Create the namespace and set its id in `wrangler.toml`:

```bash
npx wrangler kv namespace create DOMAIN_CONFIG
```

Copy the returned **id** and in `wrangler.toml` set:

```toml
[[kv_namespaces]]
binding = "DOMAIN_CONFIG"
id = "YOUR_ID_HERE"
```

(Optional, for local dev) Create a preview namespace and add under `[env.dev]` or use the same id for dev:

```bash
npx wrangler kv namespace create DOMAIN_CONFIG --preview
```

## 2. Login to Cloudflare

**Option A: OAuth (interactive terminal)**

```bash
npx wrangler login
```

**Option B: API token (avoids EBADF in non-interactive environments)**

1. Create token at https://dash.cloudflare.com/profile/api-tokens (e.g. “Edit Cloudflare Workers”).
2. `export CLOUDFLARE_API_TOKEN="your_token"`

## 3. Set secrets

```bash
npx wrangler secret put RESEND_API_KEY
npx wrangler secret put RESEND_FROM_EMAIL
npx wrangler secret put RESEND_TO_EMAIL
```

**Optional – hide UI/API behind a secret path (non-indexable):**

Set `SECRET_PATH` to a random alphanumeric string (e.g. `x7k2m9pgh64F4hyr`). The UI and all API routes then live under `/{SECRET_PATH}/`; the root `/` returns 404 so the app is not discoverable. The UI page also sends `noindex, nofollow` so search engines do not index it.

```bash
npx wrangler secret put SECRET_PATH
# Enter your random string when prompted (letters and numbers only).
```

Or set in `wrangler.toml` under `[vars]`: `SECRET_PATH = "x7k2m9pgh64F4hyr"`. After deploy, open `https://your-worker.workers.dev/x7k2m9pgh64F4hyr` for the UI; config is at `/x7k2m9pgh64F4hyr/config`, run at `/x7k2m9pgh64F4hyr/run`, etc.

**Optional – admin-only access (recommended with SECRET_PATH):**

There is no sign-up; a single admin account is configured via secrets. If you set `ADMIN_PASSWORD`, the UI and all config/run/status/test-email endpoints require login. Use a strong password.

```bash
npx wrangler secret put ADMIN_USER     # optional; default "admin"
npx wrangler secret put ADMIN_PASSWORD # required to enable auth
npx wrangler secret put ADMIN_SESSION_SECRET  # optional; auto-derived from password if not set
```

- **ADMIN_USER**: Username (default `admin`).
- **ADMIN_PASSWORD**: Password; required to turn on auth. Stored encrypted by Cloudflare.
- **ADMIN_SESSION_SECRET**: Used to sign session cookies. If omitted, a value is derived from the password.

After login, a signed session cookie is set (HttpOnly, Secure, SameSite=Strict, 24h). You can also use HTTP Basic Auth (username + password in the `Authorization` header) for API calls.

**Optional – skip cron at night (quiet hours):**

To avoid running the automatic check late at night, set these **vars** (in dashboard or `wrangler.toml` under `[vars]`):

- **QUIET_START_HOUR** – start of quiet window (hour in local time, 0–23). Example: `23` = 11pm.
- **QUIET_END_HOUR** – end of quiet window. Example: `6` = 6am.
- **TZ_OFFSET_HOURS** – offset from UTC for your timezone. Example: `7` for GMT+7.

With `QUIET_START_HOUR=23`, `QUIET_END_HOUR=6`, `TZ_OFFSET_HOURS=7`, the cron will skip runs between 11pm and 6am (GMT+7). Manual “Check links now” in the UI is not skipped.

**Optional – skip during weekly maintenance (e.g. Thursday 6am–9am):**

- **QUIET_MAINTENANCE_DAY** – weekday in local time (Monday=0, Tuesday=1, …, Thursday=3, Sunday=6). Example: `3` = Thursday.
- **QUIET_MAINTENANCE_START_HOUR** – start hour (0–23). Example: `6` = 6am.
- **QUIET_MAINTENANCE_END_HOUR** – end hour (exclusive). Example: `9` = 9am.

With `QUIET_MAINTENANCE_DAY=3`, `QUIET_MAINTENANCE_START_HOUR=6`, `QUIET_MAINTENANCE_END_HOUR=9`, and the same **TZ_OFFSET_HOURS**, the cron will also skip runs on Thursday between 6am and 9am (local time).

## 4. Deploy

```bash
npx wrangler deploy
```

## 5. Configure domains via UI

Open the worker URL (e.g. `https://domain-checker.<account>.workers.dev/`):

- **Active domains**: one per line (slot 1, 2, …).
- **Backup domains**: one per line. These are used when an active domain goes down.
- Click **Save config** to store the JSON in KV.
- **Run failover now** runs the check once and applies replacements.

## How it works

- **Config** is split in KV: key **active** holds a JSON object like `{ "FB": "https://kubagold.net", "LP": "https://kubagold.net", "SEO": "https://kubamas.net" }`; key **backups** holds a JSON array of URLs. The API `GET/PUT /api/config` still uses the combined shape `{ "active": { ... }, "backups": [ ... ] }`.

- **Cron** (every 15 minutes) runs failover logic:
  - For each active slot, the worker checks: HTTP 200 and domain not blocked (trustpositif).
  - If an active domain is down:
    - It tries backups in order. The **first backup that returns 200 and is not blocked** is promoted to that slot and removed from backups.
    - If no backup is valid, the slot is replaced with another active domain (if any) and an email is sent.
    - If all active are down and there are no backups, an email is sent.

- **Emails** are sent when:
  - A slot is replaced with another active domain because no backup was available.
  - All active domains are down and no backups are left.

## Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Config UI (edit active + backup lists, save, run failover) |
| `GET /api/config` | Return current config JSON |
| `PUT /api/config` | Update config (body: `{ "active": [], "backups": [] }`) |
| `GET /api/run` or `GET /check` | Run failover once and return result JSON |
| `GET /test` | Test trustpositif check on sample domains |
| `GET /test-api?domain=example.com` | Test trustpositif API for one domain |

## Verify

- **UI**: Open `https://<your-worker>.workers.dev/`, add domains, save, then “Run failover now”.
- **Logs**: `npx wrangler tail`
- **Config**: `curl https://<your-worker>.workers.dev/api/config`

## Troubleshooting

- **KV not found**: Ensure `wrangler.toml` has the correct KV namespace `id` after running `wrangler kv namespace create DOMAIN_CONFIG`.
- **Emails not sending**: Check Resend secrets and that from/to addresses are verified.
- **EBADF on login**: Use an API token or run `npx wrangler login` in your local terminal.
