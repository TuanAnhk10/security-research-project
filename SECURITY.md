# Security Policy & Responsible Disclosure Statement

## 1. Purpose of This Repository

This repository (`security-research-project`) is an educational and architectural case study demonstrating common security pitfalls in modern multi-tier streaming and EdTech platforms (specifically involving **Next.js App Router React Server Components**, **Spring Boot REST APIs**, **Shaka Packager HLS AES-128 DRM**, and **Cloudflare R2 / S3 Object Storage**).

All research, scripts, and documentation contained herein are published strictly for:
- **Defensive Engineering & Application Security (AppSec)**: Helping software architects design airtight authorization boundaries across microservices.
- **Offensive Security Research & Methodology**: Demonstrating structured grey/black-box penetration testing methodology, cryptographic stream analysis, and defense-in-depth remediation.

---

## 2. Strict Redaction & Sanitization Standard

To uphold ethical security research standards and protect intellectual property:
1. **Zero Production Identifiers**: All references to real-world domains, IP addresses, or organization names have been replaced with RFC 2606 / synthetic lab domains (`lms.edtech-target.example`, `shaka.media-core.example`, `r2.storage-edge.example`).
2. **Zero Real Cryptographic Material**: All AES-128 keys (`encryptionKey`) and Initialization Vectors (`encryptionKeyId`) in [`evidence/`](./evidence/) and [`lab/`](./lab/) are deterministically generated synthetic keys used solely by the local mock server.
3. **Zero Copyrighted Content**: No real video segments (`.ts`, `.mp4`) or proprietary PDF documents are stored in or distributed by this repository.
4. **Local Reproducibility Only**: The proof-of-concept tools in [`scripts/`](./scripts/) and automated tests in [`tests/`](./tests/) target the local mock environment ([`lab/mock_edtech_stack.py`](./lab/mock_edtech_stack.py)) bound to `127.0.0.1`.

---

## 3. Reporting Security Issues

If you discover a bug in the local lab simulator or wish to discuss the remediation patterns documented in [`docs/remediation.md`](./docs/remediation.md), please open an issue or contact the repository maintainer directly via GitHub.
