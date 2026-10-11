#!/usr/bin/env python3
"""
Cryptographic HLS AES-128-CBC Stream Decryptor & MPEG-TS Sync Verifier.
Demonstrates how leaked `encryptionKey` (Base64) and `encryptionKeyId` (Hex IV)
from FIND-01 decrypt raw 1080p `.ts` segments fetched via FIND-02.
"""
from __future__ import annotations

import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

MPEG_TS_PACKET_SIZE = 188
MPEG_TS_SYNC_BYTE = 0x47


def decrypt_hls_aes128_segment(
    encrypted_bytes: bytes,
    encryption_key_b64: str,
    encryption_key_id_hex: str,
) -> bytes:
    """
    Decrypts an AES-128-CBC encrypted HLS MPEG-TS segment using the Base64-encoded
    16-byte key and 32-character hex initialization vector (IV).
    """
    raw_key = base64.b64decode(encryption_key_b64)
    if len(raw_key) != 16:
        raise ValueError(f"Expected 16-byte AES-128 key, got {len(raw_key)} bytes")

    clean_hex = encryption_key_id_hex.lower().removeprefix("0x")
    iv = bytes.fromhex(clean_hex)
    if len(iv) != 16:
        raise ValueError(f"Expected 16-byte IV, got {len(iv)} bytes")

    if len(encrypted_bytes) % 16 != 0:
        raise ValueError("Ciphertext length must be a multiple of 16 bytes")

    cipher = AES.new(raw_key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted_bytes)

    try:
        decrypted = unpad(decrypted_padded, AES.block_size)
    except ValueError:
        decrypted = decrypted_padded

    return decrypted


def verify_mpeg_ts_sync(decrypted_bytes: bytes, min_packets: int = 2) -> bool:
    """
    Verifies that decrypted bytes form a valid MPEG-2 Transport Stream (MPEG-TS)
    by checking for the canonical 0x47 sync byte every 188 bytes.
    """
    if len(decrypted_bytes) < MPEG_TS_PACKET_SIZE * min_packets:
        return False

    for pkt_idx in range(min_packets):
        offset = pkt_idx * MPEG_TS_PACKET_SIZE
        if decrypted_bytes[offset] != MPEG_TS_SYNC_BYTE:
            return False
    return True
