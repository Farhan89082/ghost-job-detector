"""
Ghost Job Detector v2 — Flask API
"""

import csv
import io
import json
import os
import uuid
import threading
from datetime import datetime

from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS

from detector import analyze_batch, GHOST_JOB_REASONS

app = Flask(__name__, static_folder="../frontend", static_url_path="")
CORS(app)

# In-memory store (swap for Supabase/SQLite for production)
analysis_jobs: dict[str, dict] = {}


# ── Helpers ──────────────────────────────────────────────────────────────────

def parse_csv(content: str) -> list[dict]:
    reader = csv.DictReader(io.StringIO(content))
    ALIASES = {
        "title":       ["title", "job title", "position", "role", "job_title"],
        "company":     ["company", "company name", "employer", "organization"],
        "location":    ["location", "city", "place", "job location"],
        "posted_date": ["posted date", "date posted", "posted_date", "date",
                        "listing date", "posting date", "posted on"],
        "apply_link":  ["apply link", "apply url", "link", "url", "apply_link"],
        "description": ["description", "job description", "details", "summary"],
    }
    headers    = reader.fieldnames or []
    header_map = {}
    for field, aliases in ALIASES.items():
        for h in headers:
            if h.strip().lower() in aliases:
                header_map[field] = h
                break

    jobs = []
    for row in reader:
        job = {f: row.get(col, "").strip() for f, col in header_map.items()}
        if job.get("title") and job.get("company"):
            jobs.append(job)
    return jobs


def _build_summary(results: list[dict]) -> dict:
    scores = [r.get("ghost_score", 0) for r in results]
    return {
        "total":       len(results),
        "high_risk":   sum(1 for r in results if r.get("ghost_score", 0) >= 70),
        "suspicious":  sum(1 for r in results if 45 <= r.get("ghost_score", 0) < 70),
        "low_risk":    sum(1 for r in results if 20 <= r.get("ghost_score", 0) < 45),
        "likely_real": sum(1 for r in results if r.get("ghost_score", 0) < 20),
        "avg_score":   round(sum(scores) / len(scores), 1) if scores else 0,
        "duplicates":  sum(1 for r in results if r.get("duplicate_info", {}).get("is_duplicate")),
        "reposts":     sum(1 for r in results if r.get("duplicate_info", {}).get("is_repost")),
        "scam_flags":  sum(1 for r in results if r.get("scam_indicators")),
    }


def _run_analysis(job_id: str, jobs: list[dict]):
    analysis_jobs[job_id].update({"status": "running", "total": len(jobs)})

    def progress(current, total):
        analysis_jobs[job_id]["progress"]    = current
        analysis_jobs[job_id]["current_job"] = jobs[current - 1].get("title", "")

    try:
        results = analyze_batch(jobs, progress_callback=progress)
        analysis_jobs[job_id].update({
            "status":       "complete",
            "results":      results,
            "summary":      _build_summary(results),
            "completed_at": datetime.now().isoformat(),
        })
    except Exception as e:
        analysis_jobs[job_id].update({"status": "error", "error": str(e)})


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("../frontend", "index.html")


@app.route("/api/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    if not f.filename or not f.filename.endswith(".csv"):
        return jsonify({"error": "Please upload a .csv file"}), 400

    jobs = parse_csv(f.read().decode("utf-8-sig"))
    if not jobs:
        return jsonify({"error": "No valid rows found. CSV needs 'title' and 'company' columns."}), 400
    if len(jobs) > 200:
        return jsonify({"error": "Max 200 jobs per upload (to avoid rate-limiting)."}), 400

    job_id = str(uuid.uuid4())
    analysis_jobs[job_id] = {
        "id": job_id, "status": "pending",
        "jobs_parsed": len(jobs), "created_at": datetime.now().isoformat(),
        "progress": 0, "total": len(jobs),
    }
    threading.Thread(target=_run_analysis, args=(job_id, jobs), daemon=True).start()
    return jsonify({"job_id": job_id, "jobs_found": len(jobs)})


@app.route("/api/status/<job_id>")
def status(job_id: str):
    j = analysis_jobs.get(job_id)
    if not j:
        return jsonify({"error": "Not found"}), 404
    return jsonify({
        "status":      j["status"],
        "progress":    j.get("progress", 0),
        "total":       j.get("total", 0),
        "current_job": j.get("current_job", ""),
        "error":       j.get("error"),
    })


@app.route("/api/results/<job_id>")
def results(job_id: str):
    j = analysis_jobs.get(job_id)
    if not j:
        return jsonify({"error": "Not found"}), 404
    if j["status"] != "complete":
        return jsonify({"error": "Not complete yet"}), 202
    return jsonify({
        "summary":      j.get("summary", {}),
        "results":      j.get("results", []),
        "completed_at": j.get("completed_at"),
    })


@app.route("/api/export/<job_id>")
def export(job_id: str):
    j = analysis_jobs.get(job_id)
    if not j or j["status"] != "complete":
        return jsonify({"error": "Results not available"}), 404

    out = io.StringIO()
    fields = [
        "title", "company", "location", "posted_date",
        "ghost_score", "verdict", "confidence",
        "reasons", "caveats", "scam_indicators",
        "is_duplicate", "is_repost",
        "domain", "careers_url", "official_jobs_count", "analyzed_at",
    ]
    w = csv.DictWriter(out, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in j["results"]:
        row = {**r}
        row["reasons"]         = "; ".join(r.get("reasons", []))
        row["caveats"]         = "; ".join(r.get("caveats", []))
        row["scam_indicators"] = "; ".join(s["label"] for s in r.get("scam_indicators", []))
        row["is_duplicate"]    = r.get("duplicate_info", {}).get("is_duplicate", False)
        row["is_repost"]       = r.get("duplicate_info", {}).get("is_repost", False)
        w.writerow(row)

    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ghost_jobs_{job_id[:8]}.csv"},
    )


@app.route("/api/why-ghost-jobs")
def why_ghost_jobs():
    """Educational content — why companies post ghost jobs."""
    return jsonify(GHOST_JOB_REASONS)


@app.route("/api/demo")
def demo():
    return jsonify({
        "summary": {
            "total": 5, "high_risk": 1, "suspicious": 2,
            "low_risk": 1, "likely_real": 1,
            "avg_score": 46.8, "duplicates": 1, "reposts": 1, "scam_flags": 1,
        },
        "results": [
            {
                "title": "Senior Software Engineer", "company": "Acme Corp",
                "location": "New York, NY", "posted_date": "2024-08-10",
                "ghost_score": 78, "verdict": "HIGH RISK", "verdict_color": "red",
                "confidence": "HIGH",
                "confidence_note": "Multiple data points gathered — score is well-supported",
                "reasons": [
                    "No title match found on official careers page",
                    "Posting is 248 days old — most real jobs close within 30–60 days",
                    "No direct application URL in listing",
                ],
                "evidence": [
                    "Domain resolved: acmecorp.com",
                    "Careers page found at acmecorp.com/careers",
                    "Searched 12 official listings — best match was 34%",
                ],
                "caveats": [
                    "The role may exist on a third-party ATS not scraped by this tool.",
                    "Use this as a prompt to investigate, not a final verdict.",
                ],
                "scam_indicators": [],
                "duplicate_info": {},
                "domain": "acmecorp.com",
                "careers_url": "https://acmecorp.com/careers",
                "official_jobs_count": 12,
                "signals": [
                    {"id": "no_domain",    "label": "Domain not found",        "pts": 25, "triggered": False},
                    {"id": "not_on_site",  "label": "No title match on site",  "pts": 30, "triggered": True},
                    {"id": "stale",        "label": "Very stale (248d old)",   "pts": 20, "triggered": True},
                    {"id": "no_apply",     "label": "No apply link",           "pts":  8, "triggered": True},
                    {"id": "duplicate",    "label": "No duplicates",           "pts": 10, "triggered": False},
                    {"id": "repost",       "label": "No repost detected",      "pts": 12, "triggered": False},
                    {"id": "scam",         "label": "No scam language",        "pts": 25, "triggered": False},
                    {"id": "vague",        "label": "Specific title",          "pts":  5, "triggered": False},
                ],
            },
            {
                "title": "Marketing Manager", "company": "TechFlow Inc",
                "location": "Remote", "posted_date": "2024-11-05",
                "ghost_score": 55, "verdict": "SUSPICIOUS", "verdict_color": "orange",
                "confidence": "MEDIUM",
                "confidence_note": "Some evidence gathered — treat score as indicative, not conclusive",
                "reasons": [
                    "Weak title match on official site (61% similarity)",
                    "Posting is 160 days old — above average listing age",
                    "Same role at this company has been reposted 2 time(s)",
                ],
                "evidence": [
                    "Domain resolved: techflow.io",
                    "Careers page found at techflow.io/jobs",
                    "Fuzzy title match: 61% — ambiguous",
                    "Apply link present: https://techflow.io/apply/mm-2024",
                ],
                "caveats": [
                    "Reposting can also indicate a hard-to-fill role, not necessarily a ghost job.",
                ],
                "scam_indicators": [],
                "duplicate_info": {"is_repost": True, "repost_instances": [
                    {"index": 4, "date": "2024-09-15", "title": "Marketing Manager"}
                ]},
                "domain": "techflow.io",
                "careers_url": "https://techflow.io/jobs",
                "official_jobs_count": 7,
                "signals": [
                    {"id": "no_domain",   "label": "Domain not found",              "pts": 25, "triggered": False},
                    {"id": "weak_match",  "label": "Weak title match (61%)",        "pts": 12, "triggered": True},
                    {"id": "stale",       "label": "Aging (160d old)",              "pts": 10, "triggered": True},
                    {"id": "no_apply",    "label": "Apply link present",            "pts":  8, "triggered": False},
                    {"id": "duplicate",   "label": "No duplicates",                 "pts": 10, "triggered": False},
                    {"id": "repost",      "label": "Reposted 2x",                   "pts": 12, "triggered": True},
                    {"id": "scam",        "label": "No scam language",              "pts": 25, "triggered": False},
                    {"id": "vague",       "label": "Specific title",                "pts":  5, "triggered": False},
                ],
            },
            {
                "title": "Work From Home Assistant — Earn $800/day, No Experience!",
                "company": "QuickHire Solutions", "location": "Remote",
                "posted_date": "2025-01-18",
                "ghost_score": 66, "verdict": "SUSPICIOUS", "verdict_color": "orange",
                "confidence": "MEDIUM",
                "confidence_note": "Scam language present — manual verification strongly recommended",
                "reasons": [
                    "Suspicious language: Unrealistic daily pay claim",
                    "Suspicious language: WFH + no experience combo",
                    "Suspicious language: Vague experience requirement",
                    "Could not resolve company's official website",
                ],
                "evidence": [
                    "Could not resolve company domain — careers page check skipped",
                ],
                "caveats": [
                    "Scam language patterns are based on common fraud indicators but are not definitive.",
                ],
                "scam_indicators": [
                    {"label": "Unrealistic daily pay claim"},
                    {"label": "WFH + no experience combo"},
                    {"label": "Vague experience requirement"},
                ],
                "duplicate_info": {},
                "domain": None,
                "careers_url": None,
                "official_jobs_count": None,
                "signals": [
                    {"id": "no_domain",  "label": "Domain not found",     "pts": 25, "triggered": True},
                    {"id": "not_on_site","label": "Not on official site",  "pts": 20, "triggered": False},
                    {"id": "stale",      "label": "Recent (85d old)",      "pts": 20, "triggered": False},
                    {"id": "no_apply",   "label": "No apply link",         "pts":  8, "triggered": True},
                    {"id": "duplicate",  "label": "No duplicates",         "pts": 10, "triggered": False},
                    {"id": "repost",     "label": "No repost detected",    "pts": 12, "triggered": False},
                    {"id": "scam",       "label": "3 scam indicator(s)",   "pts": 24, "triggered": True},
                    {"id": "vague",      "label": "Specific title",        "pts":  5, "triggered": False},
                ],
            },
            {
                "title": "Data Analyst", "company": "DataBridge",
                "location": "Austin, TX", "posted_date": "2025-02-15",
                "ghost_score": 18, "verdict": "LIKELY REAL", "verdict_color": "green",
                "confidence": "HIGH",
                "confidence_note": "Multiple data points gathered — score is well-supported",
                "reasons": [],
                "evidence": [
                    "Domain resolved: databridge.com",
                    "Careers page found at databridge.com/jobs",
                    "Strong title match found on official site (94%): 'Data Analyst – Operations'",
                    "Apply link present: https://databridge.com/jobs/da-2025",
                    "Posted 57 days ago — within normal range",
                ],
                "caveats": [],
                "scam_indicators": [],
                "duplicate_info": {},
                "domain": "databridge.com",
                "careers_url": "https://databridge.com/jobs",
                "official_jobs_count": 9,
                "signals": [
                    {"id": "no_domain",  "label": "Domain not found",     "pts": 25, "triggered": False},
                    {"id": "not_on_site","label": "Title found on site",   "pts": 30, "triggered": False},
                    {"id": "stale",      "label": "Recent (57d old)",      "pts": 20, "triggered": False},
                    {"id": "no_apply",   "label": "Apply link present",    "pts":  8, "triggered": False},
                    {"id": "duplicate",  "label": "No duplicates",         "pts": 10, "triggered": False},
                    {"id": "repost",     "label": "No repost detected",    "pts": 12, "triggered": False},
                    {"id": "scam",       "label": "No scam language",      "pts": 25, "triggered": False},
                    {"id": "vague",      "label": "Specific title",        "pts":  5, "triggered": False},
                ],
            },
            {
                "title": "Senior Software Engineer", "company": "Acme Corp",
                "location": "New York, NY", "posted_date": "2024-08-10",
                "ghost_score": 88, "verdict": "HIGH RISK", "verdict_color": "red",
                "confidence": "HIGH",
                "confidence_note": "Multiple data points gathered — score is well-supported",
                "reasons": [
                    "No title match found on official careers page",
                    "Posting is 248 days old",
                    "This exact listing appears 2 times in your uploaded CSV",
                ],
                "evidence": [
                    "Domain resolved: acmecorp.com",
                    "Careers page found at acmecorp.com/careers",
                    "Searched 12 official listings — best match was 34%",
                ],
                "caveats": ["The role may exist on a third-party ATS not scraped by this tool."],
                "scam_indicators": [],
                "duplicate_info": {"is_duplicate": True, "duplicate_count": 2, "duplicate_indices": [0]},
                "domain": "acmecorp.com",
                "careers_url": "https://acmecorp.com/careers",
                "official_jobs_count": 12,
                "signals": [
                    {"id": "not_on_site", "label": "No title match on site", "pts": 30, "triggered": True},
                    {"id": "stale",       "label": "Very stale (248d old)",  "pts": 20, "triggered": True},
                    {"id": "no_apply",    "label": "No apply link",          "pts":  8, "triggered": True},
                    {"id": "duplicate",   "label": "Duplicate (2x in batch)","pts": 10, "triggered": True},
                ],
            },
        ],
        "completed_at": datetime.now().isoformat(),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
