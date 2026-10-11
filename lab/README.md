# 🧪 Local Vulnerable Multi-Service Lab (`lab/`)

## 1. Overview

To allow security engineers, researchers, and developers to safely reproduce all six vulnerability classes (`FIND-01` through `FIND-06`) without touching any external network, [`mock_edtech_stack.py`](./mock_edtech_stack.py) implements an in-memory, multi-endpoint simulator that replicates the exact vulnerable behavior of:
1. **Next.js App Router RSC Flight Stream** (`/vi/gian-sach/dstln`, `/vi/khoa-hoc/{id}` with header `RSC: 1`) leaking `DRAFT` book entities, curriculum node UUIDs, and sequential seeded UUIDs (`a0000000-0000-0000-0000-000000000001`).
2. **Client-Side Turbopack Bundle** (`/_next/static/chunks/2tv67cm3-xz1_.js`) exposing internal API endpoints and upstream infrastructure URLs.
3. **Differential Authorization on Core LMS**:
   - `GET /api/shaka/token?videoId={id}` $\rightarrow$ `HTTP 401 Unauthorized`
   - `GET /api/shaka/status/{id}` $\rightarrow$ `HTTP 200 OK` (leaking `encryptionKey` Base64 & `encryptionKeyId` Hex IV!)
4. **Unauthenticated Shaka Transcoding Cluster**:
   - `GET /api/media` $\rightarrow$ `HTTP 200 OK` (full video catalog + AES-128 keys)
   - `GET /api/auth/token` $\rightarrow$ `HTTP 200 OK` (anonymous playback JWT)
   - `POST /api/upload/init` $\rightarrow$ `HTTP 200 OK` (unauthenticated chunked upload initialization)
5. **Public Object Storage Bucket (`R2`) & Real AES-128-CBC Encrypted MPEG-TS**:
   - `GET /hls/{id}/master.m3u8` & `GET /hls/{id}/video_1080p.m3u8` $\rightarrow$ `HTTP 200 OK`
   - `GET /hls/{id}/parts/w0/seg_1080p_w0_0000.ts` $\rightarrow$ Returns a real **AES-128-CBC encrypted MPEG-TS segment** (containing valid 188-byte packets starting with sync byte `0x47`) encrypted on the fly with the video's `encryptionKey` and `encryptionKeyId`!
6. **Document BOLA & Order Payment Oracle**:
   - `GET /api/documents/{id}/file` $\rightarrow$ `HTTP 200 OK` (`%PDF-1.7` stream for both active and replaced/historical UUIDs)
   - `GET /api/book-orders/{id}/check-payment` $\rightarrow$ Unauthenticated database lookup (`200 OK` / `404 BookOrder not found`).

---

## 2. Running the Lab Server

```bash
python lab/mock_edtech_stack.py --host 127.0.0.1 --port 18080
```

Once started, run the audit tools in [`../scripts/`](../scripts/) or execute `pytest` in [`../tests/`](../tests/).
