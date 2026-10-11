# 📋 Detailed Technical Findings (CVSS v3.1 & OWASP API Top 10:2023)

---

## Finding Summary Matrix

| ID | Title | Severity | CVSS v3.1 Score & Vector | OWASP API 2023 | CWE |
| :---: | :--- | :---: | :--- | :---: | :---: |
| **[`FIND-01`](#find-01)** | Unauthenticated Mass Exposure of Media Catalog (312 Videos) & AES-128 DRM Keys | 🔴 **CRITICAL** | **9.8** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) | `API1:2023`<br>`API5:2023` | `CWE-306`<br>`CWE-522` |
| **[`FIND-02`](#find-02)** | Direct Public Cloudflare R2 Bucket Access Bypassing Media CDN JWT Gateway | 🔴 **CRITICAL** | **9.1** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`) | `API8:2023` | `CWE-284`<br>`CWE-668` |
| **[`FIND-03`](#find-03)** | Unauthenticated Chunked Video Upload & Transcoding Pipeline Exposure | 🟠 **HIGH** | **8.6** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`) | `API4:2023`<br>`API2:2023` | `CWE-306`<br>`CWE-400` |
| **[`FIND-04`](#find-04)** | Broken Object Level Authorization (BOLA) on Document Stream & Replaced Records | 🟠 **HIGH** | **7.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`) | `API1:2023` | `CWE-639` |
| **[`FIND-05`](#find-05)** | Unauthenticated Order Payment Status Oracle & Predictable Seeded UUIDs | 🟡 **MEDIUM** | **6.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`) | `API1:2023` | `CWE-330`<br>`CWE-639` |
| **[`FIND-06`](#find-06)** | Next.js RSC Flight Stream Over-Posting of `DRAFT` Entities & Syllabus Trees | 🟡 **MEDIUM** | **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`) | `API3:2023` | `CWE-200`<br>`CWE-213` |

---

<a id="find-01"></a>
## 1. `[FIND-01]` Unauthenticated Mass Exposure of Media Catalog (312 Videos) & AES-128 DRM Keys

- **Severity**: 🔴 **CRITICAL** (CVSS v3.1: **9.8** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
- **Affected Endpoints**:
  - `GET https://shaka.media-core.example/api/media`
  - `GET https://shaka.media-core.example/api/auth/token`
  - `GET https://lms.edtech-target.example/api/shaka/status/{videoId}`
- **OWASP / CWE**: `API1:2023` (Broken Object Level Authorization), `API5:2023` (Broken Function Level Authorization), `CWE-306` (Missing Authentication for Critical Function), `CWE-522` (Insufficiently Protected Credentials).

### Technical Description
The platform encrypts all HLS video streams using `AES-128-CBC`. To prevent unauthorized playback, the core LMS backend enforces authentication on `GET /api/shaka/token?videoId={id}` (`HTTP 401`). However, two critical implementation flaws bypass this control:
1. **Upstream Transcoding Cluster Exposure**: `GET https://shaka.media-core.example/api/media` is publicly accessible without authentication and returns the entire database table of **312 videos**, including each video's UUID (`id`), original filename (`originalName`), 16-byte Base64 AES-128 key (`encryptionKey`), and 16-byte Hex IV (`encryptionKeyId`). Additionally, `GET /api/auth/token` issues valid anonymous playback JWTs.
2. **Sibling Endpoint Authorization Bypass on Core LMS**: On `lms.edtech-target.example`, the endpoint `GET /api/shaka/status/{videoId}`—intended for admin polling during video upload—was configured as `permitAll()` in Spring Security and returns the raw upstream JSON object containing `encryptionKey` and `encryptionKeyId`.

### Proof of Concept (Sanitized HTTP Trace)
```http
GET /api/shaka/status/07297fe3-7b2b-42cc-86b8-749096b87c34 HTTP/1.1
Host: lms.edtech-target.example
Accept: application/json
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "id": "07297fe3-7b2b-42cc-86b8-749096b87c34",
  "originalName": "2K9 - DOT 1 - IP01 - GIAI DAP CHUONG 3.mp4",
  "status": "ready",
  "encryptionKey": "FbxOATKDyZC9bSvK6P2CAA==",
  "encryptionKeyId": "6a98f2160204d7b03603c8aa79416ff5",
  "createdAt": "2026-10-10T17:48:45.726Z"
}
```

### Business & Technical Impact
An unauthenticated attacker can harvest the complete catalog of 312 proprietary video lectures across all cohorts (Grades 10, 11, and 12) along with their cryptographic decryption keys in a single HTTP request, completely defeating the platform's DRM and paywall architecture.

---

<a id="find-02"></a>
## 2. `[FIND-02]` Direct Public Cloudflare R2 Bucket Access Bypassing Media CDN JWT Gateway

- **Severity**: 🔴 **CRITICAL** (CVSS v3.1: **9.1** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H`)
- **Affected Endpoints**:
  - `GET https://r2.storage-edge.example/hls/{videoId}/master.m3u8`
  - `GET https://r2.storage-edge.example/hls/{videoId}/video_1080p.m3u8`
  - `GET https://r2.storage-edge.example/hls/{videoId}/parts/w0/seg_1080p_w0_0000.ts`
  - `GET https://r2.storage-edge.example/lectures/pdf/{uuid}_{filename}.pdf`
- **OWASP / CWE**: `API8:2023` (Security Misconfiguration), `CWE-284` (Improper Access Control), `CWE-668` (Exposure of Resource to Wrong Sphere).

### Technical Description
While `media.storage-edge.example` acts as a JWT-validating proxy in front of HLS streams, the underlying Cloudflare R2 bucket bound to `r2.storage-edge.example` has **Public Bucket Access** enabled across `/hls/**` and `/lectures/pdf/**`. Any client can request master playlists, `1080p` variant manifests, `.ts` segments, and course PDFs directly from `r2.storage-edge.example` without presenting a `?token=` parameter.

### Proof of Concept (Sanitized HTTP Trace)
```http
GET /hls/07297fe3-7b2b-42cc-86b8-749096b87c34/master.m3u8 HTTP/1.1
Host: r2.storage-edge.example
```
```http
HTTP/1.1 200 OK
Content-Type: application/vnd.apple.mpegurl

#EXTM3U
#EXT-X-VERSION:3
#EXT-X-STREAM-INF:BANDWIDTH=600297,RESOLUTION=1920x1080,CODECS="avc1.640028,mp4a.40.2"
video_1080p.m3u8
```

---

<a id="find-03"></a>
## 3. `[FIND-03]` Unauthenticated Chunked Video Upload & Transcoding Pipeline Exposure

- **Severity**: 🟠 **HIGH** (CVSS v3.1: **8.6** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H`)
- **Affected Endpoints**:
  - `POST https://shaka.media-core.example/api/upload/init`
  - `POST https://shaka.media-core.example/api/upload/{uploadId}/chunk`
  - `POST https://shaka.media-core.example/api/upload/{uploadId}/complete`
- **OWASP / CWE**: `API4:2023` (Unrestricted Resource Consumption), `API2:2023` (Broken Authentication), `CWE-306`, `CWE-400`.

### Technical Description
The chunked upload pipeline on `shaka.media-core.example` does not validate any administrator JWT or internal API key. Sending an unauthenticated `POST /api/upload/init` request allocates a new `uploadId` (`chunkSize: 10485760` — 10 MB) and allows arbitrary binary chunks to be uploaded, transcoded via FFmpeg/Shaka Packager, and written to the R2 bucket.

### Proof of Concept
```http
POST /api/upload/init HTTP/1.1
Host: shaka.media-core.example
Content-Type: application/json

{"fileName": "security-audit-probe.mp4", "fileSize": 1048576, "totalChunks": 1}
```
```http
HTTP/1.1 200 OK
Content-Type: application/json

{"uploadId": "9a8b7c6d-1234-4abc-89ab-001122334455", "chunkSize": 10485760}
```

---

<a id="find-04"></a>
## 4. `[FIND-04]` Broken Object Level Authorization (BOLA) on Document Stream & Replaced Records

- **Severity**: 🟠 **HIGH** (CVSS v3.1: **7.5** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`)
- **Affected Endpoints**:
  - `GET https://lms.edtech-target.example/api/documents/{documentId}/file`
  - `GET https://lms.edtech-target.example/api/documents/{documentId}/file?download=true`
  - `GET https://lms.edtech-target.example/api/documents/{documentId}/preview`
- **OWASP / CWE**: `API1:2023` (Broken Object Level Authorization), `CWE-639` (Authorization Bypass Through User-Controlled Key).

### Technical Description
The `DocumentController` endpoints stream raw PDF documents (`application/pdf`) and high-resolution preview PNGs (`1536x2304`) without verifying user authentication or checking whether the document record is active/published. During assessment, in addition to all 14 active library PDFs, 2 historical document UUIDs (`95c7c225-b691-4430-b964-322c4a127f29` and `48d1cd03-dfad-45f8-b29d-a9a23f0d5be0`) that had been replaced and removed from the public UI remained directly downloadable via `/api/documents/{id}/file`.

---

<a id="find-05"></a>
## 5. `[FIND-05]` Unauthenticated Order Payment Status Oracle & Predictable Seeded UUIDs

- **Severity**: 🟡 **MEDIUM** (CVSS v3.1: **6.5** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`)
- **Affected Endpoints**:
  - `GET https://lms.edtech-target.example/api/book-orders/{uuid}/check-payment`
  - `GET https://lms.edtech-target.example/api/course-orders/installments/{uuid}/check-payment`
- **OWASP / CWE**: `API1:2023`, `CWE-330` (Use of Insufficiently Random Values), `CWE-639`.

### Technical Description
1. Both payment-verification endpoints bypass `JwtAuthenticationFilter` (`permitAll`) and directly query the database (`BookOrder not found with id: ...` / `Installment not found: ...`), allowing an unauthenticated caller who knows or enumerates an order UUID to query its payment status.
2. Database migration scripts seeded multiple tables using predictable sequential UUIDs (`a0000000-0000-0000-0000-000000000001` for books, `a1000000-...` to `a4000000-...` for LaTeX rules, and `c1000000-0000-0000-0000-000000000001` for chatbot nodes), violating UUIDv4 entropy expectations.

---

<a id="find-06"></a>
## 6. `[FIND-06]` Next.js RSC Flight Stream Over-Posting of `DRAFT` Entities & Syllabus Trees

- **Severity**: 🟡 **MEDIUM** (CVSS v3.1: **5.3** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N`)
- **Affected Endpoints**:
  - `GET https://lms.edtech-target.example/vi/gian-sach/{slug}` (with header `RSC: 1`)
  - `GET https://lms.edtech-target.example/vi/khoa-hoc/{courseId}` (with header `RSC: 1`)
- **OWASP / CWE**: `API3:2023` (Broken Object Property Level Authorization), `CWE-200`, `CWE-213`.

### Technical Description
Although the `/vi/gian-sach` book-store page displayed a *"Feature under development"* placeholder in the browser, sending a request with `RSC: 1` to individual book slugs (`/vi/gian-sach/dstln`, `/vi/gian-sach/nc9lt`) caused Next.js Server Components to serialize **18 unpublished book objects with `"status": "DRAFT"`**, along with internal forum category UUIDs and 310 curriculum node UUIDs across all 9 courses.
