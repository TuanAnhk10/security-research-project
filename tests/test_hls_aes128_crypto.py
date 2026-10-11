"""Cryptographic Unit & Integration Tests for HLS AES-128-CBC Decryption & Slide Inspection."""
from __future__ import annotations

import requests

from scripts.hls_aes128_decryptor import decrypt_hls_aes128_segment, verify_mpeg_ts_sync
from scripts.slide_frame_inspector import inspect_single_segment_metadata


def test_end_to_end_hls_aes128_decryption_and_slide_extraction(lab_base_url: str) -> None:
    """
    Chains FIND-01 (status key leak) + FIND-02 (direct R2 .ts download) + AES-128-CBC
    decryption to verify valid MPEG-TS 0x47 sync bytes and slide header extraction.
    """
    vid = "07297fe3-7b2b-42cc-86b8-749096b87c34"
    status_resp = requests.get(f"{lab_base_url}/api/shaka/status/{vid}", timeout=10)
    assert status_resp.status_code == 200
    meta = status_resp.json()

    seg_url = f"{lab_base_url}/hls/{vid}/parts/w0/seg_1080p_w0_0000.ts"
    inspection = inspect_single_segment_metadata(
        segment_url=seg_url,
        encryption_key_b64=meta["encryptionKey"],
        encryption_key_id_hex=meta["encryptionKeyId"],
    )

    assert inspection["valid_mpeg_ts_sync"] is True
    assert inspection["decrypted_size_bytes"] == 4 * 188
    markers = inspection["extracted_slide_markers"]
    assert isinstance(markers, list) and len(markers) == 4
    assert "CHUONG_1_DAO_DONG_DIEU_HOA" in markers[0]


def test_decryptor_rejects_invalid_key_length() -> None:
    """Ensures strict validation of 16-byte AES-128 keys."""
    try:
        decrypt_hls_aes128_segment(b"\x00" * 16, "c2hvcnQ=", "00" * 16)
        assert False, "Expected ValueError for non-16-byte key"
    except ValueError as exc:
        assert "16-byte AES-128 key" in str(exc)
