"""
Ghost Job Detector v2 — Tests
Run with: python -m pytest tests/ -v
"""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'backend'))

from detector import (
    calculate_ghost_score,
    check_scam_indicators,
    detect_duplicates_and_reposts,
)


# ── Scoring ──────────────────────────────────────────────

def test_no_domain_raises_score():
    job = {"title": "Engineer", "company": "Ghost Co", "apply_link": ""}
    r = calculate_ghost_score(job, None)
    assert r["ghost_score"] >= 25
    assert r["verdict"] in ("HIGH RISK", "SUSPICIOUS", "LOW RISK")

def test_strong_match_keeps_score_low():
    job = {"title": "Data Analyst", "company": "Real Co",
           "posted_date": "2025-03-01", "apply_link": "https://realco.com/jobs/1"}
    official = [{"title": "Data Analyst", "source_url": "https://realco.com/jobs"}]
    r = calculate_ghost_score(job, official)
    assert r["ghost_score"] < 30
    assert r["verdict"] in ("LIKELY REAL", "LOW RISK")

def test_stale_posting_adds_points():
    job = {"title": "PM", "company": "Co", "posted_date": "2024-01-01", "apply_link": "https://co.com"}
    official = [{"title": "PM", "source_url": "https://co.com/jobs"}]
    r = calculate_ghost_score(job, official)
    stale = [s for s in r["signals"] if "stale" in s["id"].lower() or "stale" in s["label"].lower()]
    assert any(s["triggered"] for s in stale)

def test_score_capped_at_100():
    job = {"title": "Various Positions", "company": "X", "posted_date": "2020-01-01", "apply_link": ""}
    r = calculate_ghost_score(job, None)
    assert r["ghost_score"] <= 100

def test_confidence_levels_present():
    job = {"title": "Engineer", "company": "Co", "apply_link": "https://co.com"}
    r = calculate_ghost_score(job, [{"title": "Engineer"}])
    assert r["confidence"] in ("HIGH", "MEDIUM", "LOW")

def test_caveats_present_when_no_domain():
    job = {"title": "Engineer", "company": "Unknown Corp", "apply_link": ""}
    r = calculate_ghost_score(job, None)
    assert len(r["caveats"]) >= 1

def test_reasons_populated_on_flag():
    job = {"title": "Talent Pool", "company": "No Co", "posted_date": "2023-01-01", "apply_link": ""}
    r = calculate_ghost_score(job, None)
    assert len(r["reasons"]) >= 1


# ── Scam detection ───────────────────────────────────────

def test_scam_unrealistic_pay():
    job = {"title": "Work From Home", "description": "Earn $900 per day guaranteed!"}
    hits = check_scam_indicators(job)
    assert any("pay" in h["label"].lower() or "earning" in h["label"].lower() for h in hits)

def test_scam_mlm_language():
    job = {"title": "Sales Rep", "description": "Be your own boss, multi-level opportunity"}
    hits = check_scam_indicators(job)
    assert len(hits) >= 1

def test_clean_job_no_scam():
    job = {"title": "Senior Engineer", "description": "Build scalable backend systems in Python."}
    hits = check_scam_indicators(job)
    assert len(hits) == 0

def test_scam_no_interview():
    job = {"title": "Assistant", "description": "Immediate start, no interview required."}
    hits = check_scam_indicators(job)
    assert len(hits) >= 1


# ── Duplicate / repost detection ─────────────────────────

def test_exact_duplicate_flagged():
    jobs = [
        {"title": "Engineer", "company": "Acme", "location": "NY", "posted_date": "2025-01-01"},
        {"title": "Engineer", "company": "Acme", "location": "NY", "posted_date": "2025-01-01"},
    ]
    result = detect_duplicates_and_reposts(jobs)
    assert result[0].get("is_duplicate") or result[1].get("is_duplicate")

def test_repost_detected():
    jobs = [
        {"title": "Product Manager", "company": "TechCo", "location": "Remote", "posted_date": "2024-09-01"},
        {"title": "Product Manager", "company": "TechCo", "location": "Remote", "posted_date": "2025-01-15"},
    ]
    result = detect_duplicates_and_reposts(jobs)
    assert result[0].get("is_repost") or result[1].get("is_repost")

def test_different_companies_not_duplicate():
    jobs = [
        {"title": "Engineer", "company": "Acme", "location": "NY", "posted_date": "2025-01-01"},
        {"title": "Engineer", "company": "Globex", "location": "NY", "posted_date": "2025-01-01"},
    ]
    result = detect_duplicates_and_reposts(jobs)
    assert not result.get(0, {}).get("is_duplicate")
    assert not result.get(1, {}).get("is_duplicate")

def test_unique_jobs_no_flags():
    jobs = [
        {"title": "Engineer", "company": "Acme", "location": "NY", "posted_date": "2025-01-01"},
        {"title": "Designer", "company": "Beta", "location": "LA", "posted_date": "2025-01-10"},
    ]
    result = detect_duplicates_and_reposts(jobs)
    assert result == {}


if __name__ == "__main__":
    tests = [
        test_no_domain_raises_score, test_strong_match_keeps_score_low,
        test_stale_posting_adds_points, test_score_capped_at_100,
        test_confidence_levels_present, test_caveats_present_when_no_domain,
        test_reasons_populated_on_flag, test_scam_unrealistic_pay,
        test_scam_mlm_language, test_clean_job_no_scam, test_scam_no_interview,
        test_exact_duplicate_flagged, test_repost_detected,
        test_different_companies_not_duplicate, test_unique_jobs_no_flags,
    ]
    passed = 0
    for t in tests:
        try:
            t(); print(f"  ✅ {t.__name__}"); passed += 1
        except Exception as e:
            print(f"  ❌ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed")
