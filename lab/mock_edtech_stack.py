#!/usr/bin/env python3
"""
Self-Contained Vulnerable Multi-Service EdTech & HLS DRM Lab Simulator.
Reproduces FIND-01 through FIND-06 safely on 127.0.0.1 for PoC verification and pytest testing.
"""
from __future__ import annotations

import argparse
import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Synthetic AES-128 Key (16 bytes) and IV (16 bytes) for Lab Reproduction
LAB_VIDEO_ID_1 = "07297fe3-7b2b-42cc-86b8-749096b87c34"
LAB_VIDEO_ID_2 = "39a33ad6-d535-4ce4-a115-b220d03b021f"
LAB_RAW_KEY_1 = bytes.fromhex("15bc4e013283c990bd6d2bcaa8fd8200")
LAB_IV_HEX_1 = "6a98f2160204d7b03603c8aa79416ff5"
LAB_RAW_KEY_2 = bytes.fromhex("8d963d5a35fefb60435ce33ec4d8ceb1")
LAB_IV_HEX_2 = "5d9775b0a605fe874e4ef928b9fe246e"

LAB_MEDIA_CATALOG: list[dict[str, Any]] = [
    {
        "id": LAB_VIDEO_ID_1,
        "originalName": "2K9 - DOT 1 - IP01 - GIAI DAP CHUONG 3.mp4",
        "status": "ready",
        "encryptionKey": base64.b64encode(LAB_RAW_KEY_1).decode("ascii"),
        "encryptionKeyId": LAB_IV_HEX_1,
        "createdAt": "2026-10-10T17:48:45.726Z",
    },
    {
        "id": LAB_VIDEO_ID_2,
        "originalName": "DOT 2_CHU DE 6 DO THI DAO DONG LT.mp4",
        "status": "ready",
        "encryptionKey": base64.b64encode(LAB_RAW_KEY_2).decode("ascii"),
        "encryptionKeyId": LAB_IV_HEX_2,
        "createdAt": "2026-10-09T14:20:10.112Z",
    },
]

LAB_DOCUMENTS: dict[str, dict[str, Any]] = {
    "61de531b-fb8d-4814-886c-87df5b08dd27": {
        "id": "61de531b-fb8d-4814-886c-87df5b08dd27",
        "title": "TAI LIEU ON THI GIUA HKI - LOP 11",
        "status": "PUBLISHED",
        "pdfBytes": b"%PDF-1.4\n% Lab Synthetic Active PDF Document (Grade 11 Physics)\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
    },
    "95c7c225-b691-4430-b964-322c4a127f29": {
        "id": "95c7c225-b691-4430-b964-322c4a127f29",
        "title": "TAI LIEU ON THI GIUA HKI (ARCHIVED / REPLACED RECORD)",
        "status": "REPLACED_HIDDEN",
        "pdfBytes": b"%PDF-1.7\n% Lab Synthetic Historical Replaced PDF Document (BOLA Proof)\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n",
    },
}

LAB_ORDERS: dict[str, dict[str, Any]] = {
    "a0000000-0000-0000-0000-000000000001": {
        "orderId": "a0000000-0000-0000-0000-000000000001",
        "paymentStatus": "PAID",
        "amountVnd": 299000,
    }
}


def build_synthetic_mpegts_segment(video_id: str, key: bytes, iv_hex: str) -> bytes:
    """
    Constructs a valid 4-packet MPEG-TS payload (4 * 188 = 752 bytes), each starting with
    the canonical 0x47 sync byte and containing embedded slide metadata, then encrypts it
    with AES-128-CBC (PKCS#7 padding).
    """
    packets = bytearray()
    for pkt_idx in range(4):
        pkt = bytearray(188)
        pkt[0] = 0x47  # MPEG-TS Sync Byte
        pkt[1] = 0x40 if pkt_idx == 0 else 0x00
        pkt[2] = 0x11
        pkt[3] = 0x10 | (pkt_idx & 0x0F)
        meta = f"SLIDE_HEADER|VIDEO={video_id}|PKT={pkt_idx}|CHUONG_1_DAO_DONG_DIEU_HOA".encode("utf-8")
        pkt[4 : 4 + len(meta)] = meta
        packets.extend(pkt)

    iv = bytes.fromhex(iv_hex)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes(packets), AES.block_size))


class VulnerableEdTechHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        # Silence noisy default stdout logging during unit tests
        pass

    def _send_json(self, status_code: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status_code: int, text: str, content_type: str = "text/plain; charset=utf-8") -> None:
        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status_code: int, data: bytes, content_type: str) -> None:
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        base_url = f"http://{self.headers.get('Host', '127.0.0.1:18080')}"

        # 1. Client JS Bundle (Phase 1 Recon)
        if path == "/_next/static/chunks/2tv67cm3-xz1_.js":
            js_code = (
                f'const SHAKA_URL="{base_url}";\n'
                f'const R2_PUBLIC="{base_url}";\n'
                'function getStatus(id){return fetch(`/api/shaka/status/${id}`);}\n'
                'function getToken(id){return fetch(`/api/shaka/token?videoId=${id}`);}\n'
                'function getDoc(id){return fetch(`/api/documents/${id}/file`);}\n'
            )
            self._send_text(200, js_code, "application/javascript")
            return

        # 2. Next.js RSC Flight Stream (FIND-06 & FIND-05 Seeded UUIDs)
        if path.startswith("/vi/gian-sach/") or path.startswith("/vi/khoa-hoc/"):
            is_rsc = self.headers.get("RSC") == "1"
            if is_rsc:
                flight_stream = (
                    '0:["$@1",["development",null]]\n'
                    '1:{"courseId":"c6d019de-a5f4-478c-9134-ba3db7b3e83b","title":"2K10 - VAT LY 11",'
                    '"syllabusNodes":["a1000000-0000-0000-0000-000000000001","c1000000-0000-0000-0000-000000000001"],'
                    '"draftBooks":[{"id":"a0000000-0000-0000-0000-000000000001","slug":"dstln","title":"2027 CAU HOI DUNG SAI","status":"DRAFT"}]}\n'
                )
                self._send_text(200, flight_stream, "text/x-component; charset=utf-8")
            else:
                self._send_text(200, "<html><body>Tính năng đang được phát triển</body></html>", "text/html")
            return

        # 3. Properly Protected Playback Token Endpoint (Returns 401 without Bearer token)
        if path == "/api/shaka/token":
            auth = self.headers.get("Authorization", "")
            if not auth.startswith("Bearer VALID_STUDENT_JWT"):
                self._send_json(401, {"error": "Authentication required", "status": 401})
                return
            vid = query.get("videoId", [LAB_VIDEO_ID_1])[0]
            self._send_json(200, {"videoId": vid, "token": "eyJhbGciOiJIUzI1NiJ9.e30.signature"})
            return

        # 4. Vulnerable Sibling Endpoint: GET /api/shaka/status/{videoId} (FIND-01)
        if path.startswith("/api/shaka/status/"):
            vid = path.rsplit("/", 1)[-1]
            for item in LAB_MEDIA_CATALOG:
                if item["id"] == vid:
                    self._send_json(200, item)
                    return
            self._send_json(404, {"error": "Video not found"})
            return

        # 5. Vulnerable Upstream Shaka Catalog Dump: GET /api/media (FIND-01)
        if path == "/api/media":
            self._send_json(200, LAB_MEDIA_CATALOG)
            return

        # 6. Vulnerable Upstream Shaka Anonymous Token: GET /api/auth/token (FIND-01)
        if path == "/api/auth/token":
            self._send_json(200, {"token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJwbGF5YmFjayJ9.anon_sig"})
            return

        # 7. Public Cloudflare R2 HLS Master & Variant Playlists (FIND-02)
        if path.startswith("/hls/") and path.endswith("/master.m3u8"):
            parts = path.strip("/").split("/")
            vid = parts[1]
            m3u8 = (
                "#EXTM3U\n"
                "#EXT-X-VERSION:3\n"
                '#EXT-X-STREAM-INF:BANDWIDTH=600297,RESOLUTION=1920x1080,CODECS="avc1.640028,mp4a.40.2"\n'
                f"{base_url}/hls/{vid}/video_1080p.m3u8\n"
            )
            self._send_text(200, m3u8, "application/vnd.apple.mpegurl")
            return

        if path.startswith("/hls/") and path.endswith("/video_1080p.m3u8"):
            parts = path.strip("/").split("/")
            vid = parts[1]
            rec = next((x for x in LAB_MEDIA_CATALOG if x["id"] == vid), LAB_MEDIA_CATALOG[0])
            m3u8 = (
                "#EXTM3U\n"
                "#EXT-X-VERSION:3\n"
                "#EXT-X-TARGETDURATION:4\n"
                "#EXT-X-MEDIA-SEQUENCE:0\n"
                "#EXT-X-PLAYLIST-TYPE:VOD\n"
                f'#EXT-X-KEY:METHOD=AES-128,URI="{base_url}/api/keys/{vid}",IV=0x{rec["encryptionKeyId"]}\n'
                "#EXTINF:4.000000,\n"
                f"{base_url}/hls/{vid}/parts/w0/seg_1080p_w0_0000.ts\n"
                "#EXT-X-ENDLIST\n"
            )
            self._send_text(200, m3u8, "application/vnd.apple.mpegurl")
            return

        # 8. Public Cloudflare R2 Encrypted .ts Segment (FIND-02 + Cryptographic Verification)
        if path.startswith("/hls/") and path.endswith(".ts"):
            parts = path.strip("/").split("/")
            vid = parts[1]
            rec = next((x for x in LAB_MEDIA_CATALOG if x["id"] == vid), LAB_MEDIA_CATALOG[0])
            raw_key = base64.b64decode(rec["encryptionKey"])
            encrypted_ts = build_synthetic_mpegts_segment(vid, raw_key, rec["encryptionKeyId"])
            self._send_bytes(200, encrypted_ts, "video/mp2t")
            return

        # 9. Vulnerable Document Streaming Endpoint (FIND-04 BOLA)
        if path.startswith("/api/documents/") and path.endswith("/file"):
            doc_id = path.split("/")[3]
            if doc_id in LAB_DOCUMENTS:
                self._send_bytes(200, LAB_DOCUMENTS[doc_id]["pdfBytes"], "application/pdf")
                return
            self._send_json(404, {"error": f"Document not found: {doc_id}"})
            return

        # 10. Vulnerable Order Payment Status Endpoint (FIND-05)
        if path.startswith("/api/book-orders/") and path.endswith("/check-payment"):
            order_id = path.split("/")[3]
            if order_id in LAB_ORDERS:
                self._send_json(200, LAB_ORDERS[order_id])
                return
            self._send_json(404, {"error": f"BookOrder not found with id: {order_id}"})
            return

        self._send_json(404, {"error": "Route not found"})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        # Vulnerable Unauthenticated Upload Pipeline (FIND-03)
        if parsed.path == "/api/upload/init":
            self._send_json(
                200,
                {
                    "uploadId": "9a8b7c6d-1234-4abc-89ab-001122334455",
                    "chunkSize": 10485760,
                    "status": "initialized",
                },
            )
            return
        self._send_json(404, {"error": "Route not found"})


def start_background_lab_server(host: str = "127.0.0.1", port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    """Starts the vulnerable EdTech lab server in a daemon thread and returns (server, base_url)."""
    server = ThreadingHTTPServer((host, port), VulnerableEdTechHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://{host}:{actual_port}"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Local Vulnerable Multi-Service EdTech Lab")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=18080, help="Bind port (default: 18080)")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), VulnerableEdTechHandler)
    print(f"[+] Vulnerable EdTech Multi-Service Lab listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down lab server.")
        server.server_close()


if __name__ == "__main__":
    main()
