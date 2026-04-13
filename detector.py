"""
Ghost Job Detector v2 - Core Detection Engine
----------------------------------------------
Scores job listings for ghost/fake likelihood using multiple signals.
Always returns confidence levels + evidence — never certainty.

New in v2:
  - Duplicate & repost detection across the uploaded batch
  - Scam language indicators
  - Richer evidence objects (what we found, what we couldn't verify)
  - Confidence tiers instead of binary verdicts
"""

import re
import time
import logging
import hashlib
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin

import requests
import tldextract
from bs4 import BeautifulSoup
from rapidfuzz import fuzz

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

# ── ATS platform patterns ────────────────────────────────────────────────────
ATS_PATTERNS = {
    "greenhouse": ["greenhouse.io", "boards.greenhouse.io"],
    "lever":      ["lever.co", "jobs.lever.co"],
    "workday":    ["myworkdayjobs.com", "workday.com"],
    "ashby":      ["ashbyhq.com", "jobs.ashbyhq.com"],
    "smartrecruiters": ["smartrecruiters.com"],
    "icims":      ["icims.com"],
    "taleo":      ["taleo.net"],
    "jobvite":    ["jobvite.com"],
    "breezy":     ["breezy.hr"],
    "bamboohr":   ["bamboohr.com"],
}

# ── Scam / predatory language patterns ───────────────────────────────────────
SCAM_PATTERNS = [
    (r"unlimited\s+earning\s+potential",        "Promises unlimited earnings"),
    (r"be\s+your\s+own\s+boss",                 "MLM-style language"),
    (r"must\s+pay\s+for\s+training",            "Requires payment for training"),
    (r"no\s+experience\s+necessary",            "Vague experience requirement"),
    (r"work\s+from\s+home.{0,20}no\s+experience","WFH + no experience combo"),
    (r"guaranteed\s+(income|salary|pay)",        "Guarantees income (unusual)"),
    (r"investment\s+required",                   "Requires personal investment"),
    (r"multi.?level",                            "MLM indicator"),
    (r"pyramid",                                 "Pyramid scheme language"),
    (r"\$\d{3,}[,\s]*per\s+day",                "Unrealistic daily pay claim"),
    (r"act\s+now",                               "Pressure language"),
    (r"wire\s+transfer",                         "Wire transfer mention"),
    (r"send\s+us\s+your\s+(bank|account)",       "Requests banking info"),
    (r"processing\s+fee",                        "Charges a processing fee"),
    (r"earn\s+\$\d+\s*(k|,000)?\s*per\s+week",  "Unrealistic weekly earnings"),
    (r"no\s+interview\s+required",               "No interview required"),
    (r"immediate\s+start\s*,?\s*no\s+interview", "Immediate hire, no interview"),
    (r"re.?ship(ping)?\s+coordinator",           "Reshipping scam indicator"),
]

# ── Why companies post ghost jobs — educational content ──────────────────────
GHOST_JOB_REASONS = [
    {
        "id": "talent_pipeline",
        "title": "Building a Talent Pipeline",
        "description": (
            "Companies collect resumes speculatively — even when no role is open — "
            "so they have a pool of pre-screened candidates ready if a position opens "
            "in future. Your application becomes a future asset for them, not a "
            "current opportunity for you."
        ),
        "prevalence": "Very common",
    },
    {
        "id": "growth_signaling",
        "title": "Signaling Growth to Investors",
        "description": (
            "Active job postings are publicly visible signals of company expansion. "
            "Startups and public companies sometimes post roles they don't plan to fill "
            "immediately to project a growth narrative to investors, press, or competitors."
        ),
        "prevalence": "Common at startups & public companies",
    },
    {
        "id": "keeping_options_open",
        "title": "Keeping Options Open",
        "description": (
            "Leadership may 'approve in principle' a hire but not commit budget. The "
            "posting stays live indefinitely while internal decisions are pending. "
            "Applicants have no way to know the role is in limbo."
        ),
        "prevalence": "Very common",
    },
    {
        "id": "internal_compliance",
        "title": "Internal HR Compliance",
        "description": (
            "Many companies require a public posting before promoting internally or "
            "hiring a pre-selected candidate. The posting is a procedural formality — "
            "the decision is already made. Your application will not be considered."
        ),
        "prevalence": "Extremely common in large organisations",
    },
    {
        "id": "posting_activity",
        "title": "Maintaining Posting Activity",
        "description": (
            "Job board algorithms reward active posters with more visibility. Some "
            "companies re-post the same role repeatedly to stay near the top of search "
            "results, even when the role is filled or frozen."
        ),
        "prevalence": "Common",
    },
    {
        "id": "market_research",
        "title": "Salary & Market Research",
        "description": (
            "Posting a role and collecting applications is a free way for companies to "
            "gauge market salary expectations, skill availability, and what competitors "
            "are losing talent to. You become unpaid market research data."
        ),
        "prevalence": "Less common but documented",
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# Domain / careers page resolution
# ─────────────────────────────────────────────────────────────────────────────

def get_domain_from_company(company_name: str) -> tuple[str | None, str]:
    """
    Resolve company name → domain via DuckDuckGo (no API key needed).
    Returns (domain_or_None, evidence_note).
    """
    try:
        resp = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": f"{company_name} official careers jobs site"},
            headers=HEADERS,
            timeout=10,
        )
        soup = BeautifulSoup(resp.text, "html.parser")
        for el in soup.select(".result__url")[:4]:
            url_text = el.get_text(strip=True)
            if not url_text.startswith("http"):
                url_text = "https://" + url_text
            ext = tldextract.extract(url_text)
            if ext.domain and ext.suffix:
                domain = f"{ext.domain}.{ext.suffix}"
                if not any(b in domain for b in [
                    "linkedin", "indeed", "glassdoor", "monster",
                    "ziprecruiter", "dice", "careerbuilder", "bing", "google"
                ]):
                    return domain, f"Domain resolved via web search: {domain}"
    except Exception as e:
        logger.warning(f"Domain lookup failed for {company_name}: {e}")
    return None, "Could not resolve company domain — careers page check skipped"


def find_careers_page(domain: str) -> tuple[str | None, str]:
    """
    Given a domain, find the careers/jobs page.
    Returns (url_or_None, evidence_note).
    """
    common_paths = [
        "/careers", "/jobs", "/work-with-us", "/join-us",
        "/about/careers", "/company/careers", "/en/careers",
        "/en-us/careers", "/opportunities", "/open-positions",
        "/join", "/hiring",
    ]
    base = f"https://{domain}"
    for path in common_paths:
        url = base + path
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=True)
            if r.status_code == 200 and len(r.text) > 500:
                return url, f"Found careers page at {url}"
        except Exception:
            pass
        time.sleep(0.2)

    # Scan homepage for careers link
    try:
        r = requests.get(base, headers=HEADERS, timeout=8)
        soup = BeautifulSoup(r.text, "html.parser")
        for link in soup.find_all("a", href=True):
            href = link["href"].lower()
            text = link.get_text(strip=True).lower()
            if any(kw in href or kw in text for kw in [
                "career", "jobs", "join", "work with us", "we're hiring", "hiring"
            ]):
                full = urljoin(base, link["href"])
                return full, f"Found careers link on homepage: {full}"
    except Exception as e:
        logger.warning(f"Homepage scan failed for {domain}: {e}")

    return None, f"No careers page found at {domain} (tried {len(common_paths)} paths)"


def scrape_jobs_from_page(careers_url: str) -> tuple[list[dict], str]:
    """
    Scrape job titles from a careers page.
    Returns (jobs_list, evidence_note).
    """
    jobs = []
    try:
        r = requests.get(careers_url, headers=HEADERS, timeout=10)
        soup = BeautifulSoup(r.text, "html.parser")

        ats = next(
            (name for name, patterns in ATS_PATTERNS.items()
             if any(p in r.url for p in patterns)),
            None
        )

        selectors = [
            "h2", "h3", "h4",
            "[class*='job-title']", "[class*='position']",
            "[class*='role']", "[class*='opening']",
            "li[class*='job']", "div[class*='job']",
        ]
        JOB_KEYWORDS = [
            "engineer", "developer", "manager", "analyst", "designer",
            "director", "specialist", "coordinator", "lead", "senior",
            "junior", "associate", "head of", "vp", "vice president",
            "officer", "architect", "consultant", "scientist", "intern",
            "executive", "assistant", "administrator", "recruiter", "editor",
        ]
        seen = set()
        for sel in selectors:
            for el in soup.select(sel):
                t = el.get_text(strip=True)
                if 3 < len(t) < 90 and t not in seen:
                    if any(kw in t.lower() for kw in JOB_KEYWORDS):
                        seen.add(t)
                        jobs.append({"title": t, "source_url": careers_url})

        note = (
            f"Scraped {len(jobs)} listings from official careers page"
            + (f" (ATS: {ats})" if ats else "")
        )
        return jobs, note

    except Exception as e:
        return [], f"Failed to scrape careers page: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# Scam detection
# ─────────────────────────────────────────────────────────────────────────────

def check_scam_indicators(job: dict) -> list[dict]:
    """
    Scan title + description for predatory/scam language patterns.
    Returns list of triggered indicator dicts.
    """
    text = " ".join(filter(None, [
        job.get("title", ""),
        job.get("description", ""),
    ])).lower()

    triggered = []
    for pattern, label in SCAM_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            triggered.append({"pattern": pattern, "label": label})
    return triggered


# ─────────────────────────────────────────────────────────────────────────────
# Duplicate & repost detection (batch-level)
# ─────────────────────────────────────────────────────────────────────────────

def _job_fingerprint(job: dict) -> str:
    """Normalised fingerprint for duplicate detection."""
    title = re.sub(r"\W+", "", job.get("title", "").lower())
    company = re.sub(r"\W+", "", job.get("company", "").lower())
    location = re.sub(r"\W+", "", job.get("location", "").lower())
    return hashlib.md5(f"{title}|{company}|{location}".encode()).hexdigest()


def detect_duplicates_and_reposts(jobs: list[dict]) -> dict[int, dict]:
    """
    Scan all jobs and return a map of index → duplicate/repost info.
    A duplicate = same fingerprint.
    A repost   = same company + fuzzy-matched title with different posted_date.
    """
    fingerprint_map: dict[str, list[int]] = defaultdict(list)
    company_map:     dict[str, list[tuple[int, str, str]]] = defaultdict(list)

    for i, job in enumerate(jobs):
        fp = _job_fingerprint(job)
        fingerprint_map[fp].append(i)
        company_key = re.sub(r"\W+", "", job.get("company", "").lower())
        company_map[company_key].append((i, job.get("title", ""), job.get("posted_date", "")))

    result: dict[int, dict] = {}

    # Duplicates
    for fp, indices in fingerprint_map.items():
        if len(indices) > 1:
            for i in indices:
                result[i] = result.get(i, {})
                result[i]["is_duplicate"] = True
                result[i]["duplicate_count"] = len(indices)
                result[i]["duplicate_indices"] = [x for x in indices if x != i]

    # Reposts — same company, fuzzy title match (≥85), different date
    for company_key, entries in company_map.items():
        if len(entries) < 2:
            continue
        for a_idx, (i, title_i, date_i) in enumerate(entries):
            reposts_of_i = []
            for j, title_j, date_j in entries:
                if j == i:
                    continue
                if fuzz.token_sort_ratio(title_i.lower(), title_j.lower()) >= 85:
                    if date_i != date_j:
                        reposts_of_i.append({"index": j, "date": date_j, "title": title_j})
            if reposts_of_i:
                result[i] = result.get(i, {})
                result[i]["is_repost"] = True
                result[i]["repost_instances"] = reposts_of_i

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Ghost scoring
# ─────────────────────────────────────────────────────────────────────────────

def calculate_ghost_score(
    job: dict,
    official_jobs: list[dict] | None,
    dupe_info: dict | None = None,
    scam_hits: list[dict] | None = None,
    evidence_log: list[str] | None = None,
) -> dict:
    """
    Calculate ghost score 0–100.
    Returns full result dict including confidence tier, evidence, and caveats.

    Score is intentionally NOT presented as certainty — we always surface
    the evidence so users can make their own judgement.
    """
    score = 0
    signals = []
    reasons = []
    evidence = list(evidence_log or [])
    caveats = []

    title       = job.get("title", "")
    posted_date = job.get("posted_date", "")
    apply_link  = job.get("apply_link", "")

    # ── Signal 1: No careers page found (25 pts) ─────────────────────────────
    if official_jobs is None:
        score += 25
        signals.append({"id": "no_domain", "label": "Domain not found", "pts": 25, "triggered": True})
        reasons.append("Could not resolve company's official website")
        caveats.append(
            "Some companies use a holding company name that differs from their public brand — "
            "this alone is not proof of a ghost job."
        )
    else:
        signals.append({"id": "no_domain", "label": "Domain not found", "pts": 25, "triggered": False})

    # ── Signal 2: Careers page exists but job not found (30 pts) ─────────────
    if official_jobs is not None:
        if len(official_jobs) == 0:
            score += 20
            signals.append({"id": "not_on_site", "label": "Not on official site", "pts": 20, "triggered": True})
            reasons.append("Careers page found but appears empty or couldn't be scraped")
            caveats.append(
                "The role may be listed on a third-party ATS (Greenhouse, Workday, etc.) "
                "rather than the main website — this is very common and doesn't confirm a ghost job."
            )
        else:
            best_match = 0
            best_match_title = ""
            for oj in official_jobs:
                ratio = fuzz.token_sort_ratio(title.lower(), oj.get("title", "").lower())
                if ratio > best_match:
                    best_match = ratio
                    best_match_title = oj.get("title", "")

            if best_match < 55:
                score += 30
                signals.append({"id": "not_on_site", "label": "No title match on site", "pts": 30, "triggered": True})
                reasons.append(f"Best title match on official site: {best_match_title!r} ({best_match}% similarity)")
                evidence.append(f"Searched {len(official_jobs)} official listings — best match was {best_match}%")
                caveats.append(
                    "The job may exist under a slightly different title, on a separate ATS, "
                    "or may have been temporarily unlisted. Use this as a prompt to investigate, not a verdict."
                )
            elif best_match < 80:
                score += 12
                signals.append({"id": "weak_match", "label": f"Weak title match ({best_match}%)", "pts": 12, "triggered": True})
                reasons.append(f"Closest official listing: {best_match_title!r}")
                evidence.append(f"Fuzzy title match: {best_match}% — ambiguous")
            else:
                signals.append({"id": "not_on_site", "label": "Title found on site", "pts": 30, "triggered": False})
                evidence.append(f"Strong title match found on official site ({best_match}%): {best_match_title!r}")

    # ── Signal 3: Posting age (20 pts) ───────────────────────────────────────
    if posted_date:
        days_old = None
        for fmt in ["%Y-%m-%d", "%m/%d/%Y", "%d/%m/%Y", "%B %d, %Y", "%b %d, %Y"]:
            try:
                days_old = (datetime.now() - datetime.strptime(posted_date.strip(), fmt)).days
                break
            except ValueError:
                continue

        if days_old is not None:
            if days_old > 120:
                score += 20
                signals.append({"id": "stale", "label": f"Very stale ({days_old}d old)", "pts": 20, "triggered": True})
                reasons.append(f"Posting is {days_old} days old — most real jobs close within 30–60 days")
            elif days_old > 60:
                score += 10
                signals.append({"id": "stale", "label": f"Aging ({days_old}d old)", "pts": 10, "triggered": True})
                reasons.append(f"Posting is {days_old} days old — above average listing age")
            else:
                signals.append({"id": "stale", "label": f"Recent ({days_old}d old)", "pts": 20, "triggered": False})
                evidence.append(f"Posted {days_old} days ago — within normal range")
        else:
            signals.append({"id": "stale", "label": "Date unreadable", "pts": 5, "triggered": True})
            score += 5
    else:
        score += 8
        signals.append({"id": "stale", "label": "No post date", "pts": 8, "triggered": True})
        reasons.append("No posting date provided — age cannot be verified")

    # ── Signal 4: No apply link (8 pts) ──────────────────────────────────────
    if not apply_link:
        score += 8
        signals.append({"id": "no_apply", "label": "No apply link", "pts": 8, "triggered": True})
        reasons.append("No direct application URL in listing")
    else:
        signals.append({"id": "no_apply", "label": "Apply link present", "pts": 8, "triggered": False})
        evidence.append(f"Apply link present: {apply_link[:60]}")

    # ── Signal 5: Duplicate in batch (10 pts) ────────────────────────────────
    if dupe_info and dupe_info.get("is_duplicate"):
        count = dupe_info.get("duplicate_count", 2)
        score += 10
        signals.append({"id": "duplicate", "label": f"Duplicate ({count}x in batch)", "pts": 10, "triggered": True})
        reasons.append(f"This exact listing appears {count} times in your uploaded CSV")
    else:
        signals.append({"id": "duplicate", "label": "No duplicates", "pts": 10, "triggered": False})

    # ── Signal 6: Repost history (12 pts) ────────────────────────────────────
    if dupe_info and dupe_info.get("is_repost"):
        instances = len(dupe_info.get("repost_instances", []))
        score += 12
        signals.append({"id": "repost", "label": f"Reposted {instances}x", "pts": 12, "triggered": True})
        reasons.append(
            f"Same role at this company has been reposted {instances} time(s) with different dates"
        )
        caveats.append(
            "Reposting can also indicate a hard-to-fill role, not necessarily a ghost job."
        )
    else:
        signals.append({"id": "repost", "label": "No repost detected", "pts": 12, "triggered": False})

    # ── Signal 7: Scam indicators (up to 25 pts) ─────────────────────────────
    if scam_hits:
        scam_score = min(len(scam_hits) * 8, 25)
        score += scam_score
        signals.append({"id": "scam", "label": f"{len(scam_hits)} scam indicator(s)", "pts": scam_score, "triggered": True})
        for hit in scam_hits:
            reasons.append(f"Suspicious language: {hit['label']}")
    else:
        signals.append({"id": "scam", "label": "No scam language", "pts": 25, "triggered": False})

    # ── Signal 8: Vague title (5 pts) ────────────────────────────────────────
    vague = ["various positions", "multiple roles", "talent pool", "general application", "open application"]
    if any(v in title.lower() for v in vague):
        score += 5
        signals.append({"id": "vague", "label": "Vague title", "pts": 5, "triggered": True})
        reasons.append("Job title is generic or non-specific")
    else:
        signals.append({"id": "vague", "label": "Specific title", "pts": 5, "triggered": False})

    score = min(score, 100)

    # ── Confidence tier ───────────────────────────────────────────────────────
    # Confidence reflects how much evidence we actually gathered,
    # not how certain we are the job is fake.
    triggered_count = sum(1 for s in signals if s["triggered"])
    total_signals   = len(signals)
    evidence_ratio  = len(evidence) / max(total_signals, 1)

    if evidence_ratio > 0.5 and len(evidence) >= 3:
        confidence = "HIGH"
        confidence_note = "Multiple data points gathered — score is well-supported"
    elif len(evidence) >= 1:
        confidence = "MEDIUM"
        confidence_note = "Some evidence gathered — treat score as indicative, not conclusive"
    else:
        confidence = "LOW"
        confidence_note = "Limited evidence available — score is speculative; manual verification recommended"

    # ── Verdict label ─────────────────────────────────────────────────────────
    if score >= 70:
        verdict = "HIGH RISK"
        verdict_color = "red"
    elif score >= 45:
        verdict = "SUSPICIOUS"
        verdict_color = "orange"
    elif score >= 20:
        verdict = "LOW RISK"
        verdict_color = "yellow"
    else:
        verdict = "LIKELY REAL"
        verdict_color = "green"

    return {
        "ghost_score":      score,
        "verdict":          verdict,
        "verdict_color":    verdict_color,
        "confidence":       confidence,
        "confidence_note":  confidence_note,
        "signals":          signals,
        "reasons":          reasons,
        "evidence":         evidence,
        "caveats":          caveats,
        "scam_indicators":  scam_hits or [],
        "duplicate_info":   dupe_info or {},
    }


# ─────────────────────────────────────────────────────────────────────────────
# Single job analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_job(
    job: dict,
    dupe_info: dict | None = None,
    cached_company: dict | None = None,
) -> tuple[dict, dict]:
    """
    Analyze one job. Returns (enriched_result, company_cache_entry).
    Pass cached_company to reuse already-fetched careers data.
    """
    evidence_log = []
    official_jobs = None
    domain = None
    careers_url = None

    if cached_company:
        domain      = cached_company.get("domain")
        careers_url = cached_company.get("careers_url")
        official_jobs = cached_company.get("official_jobs")
        evidence_log += cached_company.get("evidence_log", [])
    else:
        domain, note = get_domain_from_company(job.get("company", ""))
        evidence_log.append(note)

        if domain:
            careers_url, note = find_careers_page(domain)
            evidence_log.append(note)

            if careers_url:
                official_jobs, note = scrape_jobs_from_page(careers_url)
                evidence_log.append(note)
            else:
                official_jobs = []
                evidence_log.append("No careers page found — cannot cross-check listing")

    scam_hits = check_scam_indicators(job)

    scoring = calculate_ghost_score(
        job,
        official_jobs,
        dupe_info=dupe_info,
        scam_hits=scam_hits,
        evidence_log=evidence_log,
    )

    result = {
        **job,
        "analyzed_at":           datetime.now().isoformat(),
        "domain":                domain,
        "careers_url":           careers_url,
        "official_jobs_count":   len(official_jobs) if official_jobs is not None else None,
        **scoring,
    }

    cache_entry = {
        "domain":       domain,
        "careers_url":  careers_url,
        "official_jobs": official_jobs,
        "evidence_log": evidence_log,
    }

    time.sleep(0.8)
    return result, cache_entry


# ─────────────────────────────────────────────────────────────────────────────
# Batch analysis
# ─────────────────────────────────────────────────────────────────────────────

def analyze_batch(jobs: list[dict], progress_callback=None) -> list[dict]:
    """
    Analyze a full batch.
    - Runs duplicate/repost detection first across the whole set.
    - Caches careers page data per company.
    """
    dupe_map     = detect_duplicates_and_reposts(jobs)
    company_cache: dict[str, dict] = {}
    results = []

    for i, job in enumerate(jobs):
        company_key = re.sub(r"\W+", "", job.get("company", "").lower())
        cached = company_cache.get(company_key)

        result, cache_entry = analyze_job(
            job,
            dupe_info=dupe_map.get(i),
            cached_company=cached,
        )

        if company_key not in company_cache:
            company_cache[company_key] = cache_entry

        results.append(result)

        if progress_callback:
            progress_callback(i + 1, len(jobs))

        logger.info(
            f"[{i+1}/{len(jobs)}] {job.get('title')} @ {job.get('company')} "
            f"→ {result['ghost_score']} ({result['verdict']}) "
            f"[confidence: {result['confidence']}]"
        )

    return results
