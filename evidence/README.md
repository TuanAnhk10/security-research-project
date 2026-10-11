# 🗂️ Sanitized Technical Evidence Artifacts (`evidence/`)

This directory contains sanitized, representative protocol captures demonstrating the exact structure of the vulnerabilities documented in [`../docs/findings.md`](../docs/findings.md):

1. **[`sample_shaka_media_dump.json`](./sample_shaka_media_dump.json)**:
   - Demonstrates `FIND-01`: Unauthenticated JSON responses from `GET /api/media` and `GET /api/shaka/status/{videoId}` exposing `encryptionKey` (Base64 16-byte AES-128 key) and `encryptionKeyId` (16-byte Hex IV).
2. **[`sample_hls_master_playlist.m3u8`](./sample_hls_master_playlist.m3u8)**:
   - Demonstrates `FIND-02`: Direct unauthenticated retrieval of `master.m3u8` and `video_1080p.m3u8` from the public Cloudflare R2 bucket, including the `#EXT-X-KEY:METHOD=AES-128` header.
3. **[`sample_rsc_flight_stream.txt`](./sample_rsc_flight_stream.txt)**:
   - Demonstrates `FIND-05` & `FIND-06`: Next.js App Router React Server Component (`RSC: 1`) Flight stream serializing `DRAFT` book entities, internal curriculum UUIDs, and predictable sequential migration UUIDs (`a0000000-0000-0000-0000-000000000001`).
