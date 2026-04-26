# EnchantedVision Activation Server

A small FastAPI service that:

- Validates `(hwid, key)` against a server-side database.
- Issues short-lived **Ed25519-signed tokens** the desktop app caches locally.
- Lets you generate / revoke / list keys via authenticated admin endpoints.

The desktop app embeds the Ed25519 **public** key and verifies tokens locally.
The **private** key never leaves this server.

---

## 1. One-time setup (local)

```powershell
cd server
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env
```

Edit `.env`:

- Generate an admin API key: `python -c "import secrets; print(secrets.token_urlsafe(48))"`
- Paste it into `ADMIN_API_KEY=...`

Generate the signing keypair:

```powershell
python keypair.py
```

This writes `.keys/private.pem` (KEEP SECRET) and prints the public key as a
Python literal. **Copy that literal into `EnchantedVision/EnchantedVision.py`**
(replacing the `ACTIVATION_SERVER_PUBKEY = bytes.fromhex(...)` constant).

Run locally:

```powershell
uvicorn app:app --host 0.0.0.0 --port 8080
```

Smoke test:

```powershell
curl http://localhost:8080/healthz
```

---

## 2. Generate a key for a customer

```powershell
$ADMIN = "<your ADMIN_API_KEY>"
$body = @{ name = "dereck"; hwid = "abcdef0123456789abcdef0123456789"; days = 365 } | ConvertTo-Json
curl -Method POST http://localhost:8080/admin/genkey `
     -Headers @{ "X-Admin-Key" = $ADMIN; "Content-Type" = "application/json" } `
     -Body $body
```

Response: `{"key": "<raw_key>", "key_id": "...", "expires": "..."}`. Copy that
key to the customer once. The raw key is **never stored** server-side after this.

---

## 3. Deploy options

### Fly.io (recommended free path)

```powershell
# Install flyctl: https://fly.io/docs/hands-on/install-flyctl/
fly auth signup     # or: fly auth login
fly launch --no-deploy   # accept defaults, edit fly.toml as needed
fly volumes create ev_keys --size 1
fly secrets set ADMIN_API_KEY="<paste your secret>"
fly deploy
```

Then on first boot SSH in once to generate the keypair on the server volume:

```powershell
fly ssh console -C "python keypair.py"
fly ssh console -C "cat /app/public_key_python.txt"   # copy literal into client
fly machine restart <machine_id>
```

Your URL will be `https://<app>.fly.dev`. Hard-code that into the client as
`ACTIVATION_SERVER_URL`.

### Render / Railway

Both auto-detect the `Dockerfile`. Set env vars in their dashboard:
- `ADMIN_API_KEY`
- mount a persistent disk at `/app/.keys`

### Self-hosted VPS

```bash
docker build -t ev-activation .
docker run -d --restart unless-stopped \
  -p 8080:8080 \
  -v $(pwd)/.keys:/app/.keys \
  -e ADMIN_API_KEY="$(openssl rand -base64 36)" \
  ev-activation
```

Put Caddy or Nginx in front for TLS.

---

## 4. API reference

### Public

| Method | Path        | Body                   | Response                   |
|-------:|-------------|------------------------|----------------------------|
| POST   | `/activate` | `{hwid, key}`          | `{token, expires_at}`      |
| POST   | `/refresh`  | `{token}`              | `{token, expires_at}`      |
| GET    | `/healthz`  | -                      | `{ok: true}`               |

### Admin (require `X-Admin-Key: <ADMIN_API_KEY>` header)

| Method | Path             | Body / Query                | Response                                   |
|-------:|------------------|-----------------------------|--------------------------------------------|
| POST   | `/admin/genkey`  | `{name, hwid, days, overwrite?}` | `{key, key_id, expires}`              |
| POST   | `/admin/revoke`  | `{key_id}`                  | `{revoked: true}`                          |
| GET    | `/admin/list`    | -                           | `[{key_id, name, hwid_hint, expires, ...}]` |
| GET    | `/admin/search`  | `?q=`                       | same shape                                 |

`/admin/genkey` returns 409 if the HWID is already registered. Pass
`{"overwrite": true}` to replace.

---

## 5. Security notes

- The DB never stores raw keys, only `sha256(key)`. If the DB leaks, attackers
  cannot recover working keys.
- Tokens are stateless and short-lived. Revocation takes effect at the next
  `/refresh` (max one TTL window of stale access).
- Rotating the keypair invalidates **every** outstanding token. Do this only
  if the private key has been exposed; customers will need to re-activate.
- Always run behind HTTPS (Fly.io, Render, Cloudflare all give this for free).
- Never commit `.env` or `.keys/`. The included `.gitignore` covers both.
