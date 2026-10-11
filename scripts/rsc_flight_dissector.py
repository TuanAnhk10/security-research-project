#!/usr/bin/env python3
"""
Next.js App Router RSC Flight Stream & Client Bundle Dissector (FIND-05 & FIND-06).
Extracts hidden DRAFT entities, curriculum UUIDs, and predictable sequential migration UUIDs.
"""
from __future__ import annotations

import argparse
import json
import re
from typing import Any

import requests

UUID_REGEX = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
SEEDED_UUID_REGEX = re.compile(r"\b[a-f][0-9]000000-0000-0000-0000-[0-9a-f]{12}\b", re.I)
API_ROUTE_REGEX = re.compile(r"/api/[a-zA-Z0-9_/${}-]+")


def dissect_rsc_flight_endpoint(url: str, timeout: int = 10) -> dict[str, Any]:
    """
    Sends an RSC: 1 request to a Next.js App Router route and extracts all UUIDs,
    seeded sequential UUIDs, and serialized DRAFT entities.
    """
    resp = requests.get(
        url,
        headers={
            "RSC": "1",
            "Accept": "text/x-component, */*",
        },
        timeout=timeout,
    )
    raw_text = resp.text
    all_uuids = sorted(set(UUID_REGEX.findall(raw_text)))
    seeded_uuids = sorted(set(SEEDED_UUID_REGEX.findall(raw_text)))

    draft_entities: list[dict[str, Any]] = []
    for line in raw_text.splitlines():
        if ":" in line:
            _, payload = line.split(":", 1)
            payload = payload.strip()
            if payload.startswith("{") and '"DRAFT"' in payload:
                try:
                    parsed = json.loads(payload)
                    if isinstance(parsed, dict) and "draftBooks" in parsed:
                        draft_entities.extend(parsed["draftBooks"])
                except json.JSONDecodeError:
                    pass

    return {
        "url": url,
        "http_status": resp.status_code,
        "content_type": resp.headers.get("Content-Type", ""),
        "all_uuids": all_uuids,
        "seeded_sequential_uuids": seeded_uuids,
        "draft_entities": draft_entities,
    }


def extract_endpoints_from_js_chunk(chunk_url: str, timeout: int = 10) -> list[str]:
    """Downloads a client-side JS bundle and extracts embedded /api/... route patterns."""
    resp = requests.get(chunk_url, timeout=timeout)
    return sorted(set(API_ROUTE_REGEX.findall(resp.text)))


def main() -> None:
    parser = argparse.ArgumentParser(description="Dissect Next.js RSC Flight Streams & JS Chunks")
    parser.add_argument("--url", default="http://127.0.0.1:18080/vi/gian-sach/dstln", help="Target RSC Route URL")
    args = parser.parse_args()

    report = dissect_rsc_flight_endpoint(args.url)
    print(json.dumps(report, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
