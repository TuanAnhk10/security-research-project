"""End-to-End Automated Verification Tests for FIND-01 through FIND-06."""
from __future__ import annotations

from scripts.edtech_bola_auditor import run_bola_and_key_audit
from scripts.rsc_flight_dissector import (
    dissect_rsc_flight_endpoint,
    extract_endpoints_from_js_chunk,
)


def test_all_bola_and_key_exposure_findings(lab_base_url: str) -> None:
    """Verifies that the automated auditor detects FIND-01A, FIND-01B, FIND-02, FIND-03, FIND-04, and FIND-05."""
    results = run_bola_and_key_audit(lab_base_url)
    by_id = {r.finding_id: r for r in results}

    assert by_id["FIND-01A"].vulnerable is True
    assert by_id["FIND-01A"].evidence_summary["leaked_encryption_key"] == "FbxOATKDyZC9bSvKqP2CAA=="

    assert by_id["FIND-01B"].vulnerable is True
    assert by_id["FIND-01B"].evidence_summary["total_videos_exposed"] == 2

    assert by_id["FIND-02"].vulnerable is True
    assert by_id["FIND-02"].evidence_summary["contains_ext_x_key"] is True

    assert by_id["FIND-03"].vulnerable is True
    assert "uploadId" in by_id["FIND-03"].evidence_summary

    assert by_id["FIND-04"].vulnerable is True
    assert by_id["FIND-04"].evidence_summary["pdf_magic_header"].startswith("%PDF-1.7")

    assert by_id["FIND-05"].vulnerable is True
    assert by_id["FIND-05"].evidence_summary["paymentStatus"] == "PAID"


def test_rsc_flight_stream_and_chunk_dissection(lab_base_url: str) -> None:
    """Verifies FIND-06 (RSC DRAFT entity leak) and Phase 1 JS chunk endpoint extraction."""
    rsc_report = dissect_rsc_flight_endpoint(f"{lab_base_url}/vi/gian-sach/dstln")
    assert rsc_report["http_status"] == 200
    assert "a0000000-0000-0000-0000-000000000001" in rsc_report["seeded_sequential_uuids"]
    assert len(rsc_report["draft_entities"]) == 1
    assert rsc_report["draft_entities"][0]["status"] == "DRAFT"

    routes = extract_endpoints_from_js_chunk(f"{lab_base_url}/_next/static/chunks/2tv67cm3-xz1_.js")
    assert any("/api/shaka/status/" in r for r in routes)
    assert any("/api/documents/" in r for r in routes)
