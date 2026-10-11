#!/usr/bin/env python3
"""
Single-Segment In-Memory Slide Metadata & Frame Inspector.
Demonstrates Phase 6 of the methodology: decrypting a single .ts segment in memory
to classify unlabeled media files without downloading full multi-gigabyte streams.
"""
from __future__ import annotations

import re
import requests

from scripts.hls_aes128_decryptor import decrypt_hls_aes128_segment, verify_mpeg_ts_sync


def inspect_single_segment_metadata(
    segment_url: str,
    encryption_key_b64: str,
    encryption_key_id_hex: str,
    timeout: int = 10,
) -> dict[str, object]:
    """
    Downloads a single encrypted .ts segment, decrypts it in memory via AES-128-CBC,
    verifies the MPEG-TS 0x47 packet alignment, and extracts embedded slide markers.
    """
    resp = requests.get(segment_url, timeout=timeout)
    resp.raise_for_status()

    decrypted = decrypt_hls_aes128_segment(
        resp.content,
        encryption_key_b64=encryption_key_b64,
        encryption_key_id_hex=encryption_key_id_hex,
    )
    is_valid_ts = verify_mpeg_ts_sync(decrypted)

    # Extract readable slide header strings embedded in the transport stream payload
    markers = re.findall(rb"SLIDE_HEADER\|[A-Za-z0-9_=-]+\|[A-Za-z0-9_=-]+\|[A-Za-z0-9_]+", decrypted)
    decoded_markers = [m.decode("utf-8", errors="ignore") for m in markers]

    return {
        "segment_url": segment_url,
        "encrypted_size_bytes": len(resp.content),
        "decrypted_size_bytes": len(decrypted),
        "valid_mpeg_ts_sync": is_valid_ts,
        "extracted_slide_markers": decoded_markers,
    }
