# 👻 Ghost Job Detector v2

> **Expose ghost jobs before you waste time applying — with confidence levels and evidence, not false certainty.**

A free, open-source tool that analyzes job listings from a CSV upload, cross-references each one against the company's official careers page, and returns a **Ghost Score (0–100)** along with the evidence gathered, confidence level, and caveats — so you can make an informed decision, not a snap judgement.

---

## ⚠️ Important Disclaimer

**This tool flags risks, not facts.** A high score means "worth investigating before applying" — not "definitely fake." Legitimate jobs can score poorly if:

- The company uses a third-party ATS (Greenhouse, Workday, Lever) not linked from their main site
- The listing is syndicated through an agency or staffing partner
- The company recently moved to a new careers platform
- The domain resolver matched the wrong company

Always verify independently. This tool is a starting point for your own research.

---

## ✨ What's new in v2

- 🎯 **Confidence tiers** (HIGH / MEDIUM / LOW) — reflects how much data we gathered, not certainty
- 📋 **Evidence drawer** — every card shows exactly what was checked and what was found
- ⚠️ **Caveats** — cards flag legitimate reasons a real job might appear suspicious
- 🔁 **Duplicate detection** — flags identical listings appearing multiple times in your CSV
- 🔄 **Repost history** — detects the same role at the same company reposted across different dates
- 🚨 **Scam indicators** — 18 pattern checks for predatory/fraudulent job language
- 📚 **Why Ghost Jobs panel** — education section on why companies post ghost jobs
- 🔍 **Filter by scam flags and duplicates** — new filter chips in the results view

---

## 🚀 Quick Start

### Prerequisites
- Python 3.10+

### 1. Clone
```bash
git clone https://github.com/YOUR_USERNAME/ghost-job-detector.git
cd ghost-job-detector
```

### 2. Install
```bash
cd backend
pip install -r requirements.txt
```

### 3. Run
```bash
python app.py
# Open http://localhost:5000
```

Click **"Try Demo Data"** to explore the UI without a backend running.

---

## 📋 CSV Format

| Column | Required | Notes |
|--------|----------|-------|
| `title` | ✅ | Job title |
| `company` | ✅ | Company name |
| `location` | Optional | City, state |
| `posted_date` | Optional | Improves stale-detection |
| `apply_link` | Optional | Checks for a real application URL |
| `description` | Optional | Enables scam language detection |

Column names are flexible — `job title`, `Job Title`, `jobtitle` all map correctly.

---

## 🧠 Scoring Signals

| Signal | Max Pts | What triggers it |
|--------|---------|-----------------|
| Domain not found | 25 | Can't resolve company's website |
| Job not on official site | 30 | No fuzzy title match on careers page |
| Stale posting | 20 | 90+ days old |
| No apply link | 8 | No URL in listing |
| Duplicate in batch | 10 | Same listing appears twice+ |
| Repost history | 12 | Same role, same company, different date |
| Scam indicators | 25 | Predatory/fraudulent language in title/description |
| Vague title | 5 | "Various Positions", "Talent Pool" etc. |

**Verdicts:** 70+ = HIGH RISK · 45–69 = SUSPICIOUS · 20–44 = LOW RISK · 0–19 = LIKELY REAL

**Confidence:** HIGH (3+ evidence items) · MEDIUM (1–2 items) · LOW (limited data)

---

## 🗂️ Structure

```
ghost-job-detector/
├── backend/
│   ├── app.py              # Flask REST API
│   ├── detector.py         # Detection engine (scoring, scraping, scam checks)
│   └── requirements.txt
├── frontend/
│   └── index.html          # Full dashboard (single file, no build step)
├── data/
│   └── samples/
│       └── sample_jobs.csv
├── tests/
│   └── test_detector.py    # 15 unit tests
└── README.md
```

---

## 🔧 API

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/upload` | Upload CSV → returns `job_id` |
| GET | `/api/status/:id` | Poll progress |
| GET | `/api/results/:id` | Full results JSON |
| GET | `/api/export/:id` | CSV download |
| GET | `/api/demo` | Demo data |
| GET | `/api/why-ghost-jobs` | Educational content JSON |

---

## 🔮 Future roadmap (contributions welcome)

- [ ] **Browser extension** — overlay scores directly on LinkedIn/Indeed listings
- [ ] **Supabase backend** — persistent public dashboard and community flagging
- [ ] **ATS-specific scrapers** — dedicated parsers for Greenhouse, Workday, Lever
- [ ] **Email alerts** — notify when a saved search turns up suspicious listings
- [ ] **Company reputation scores** — aggregate ghost-job history per company over time
- [ ] **Docker deployment** — one-command self-hosting

---

## 📜 License

MIT — free to use, fork, and build on.

---

## 🙏 Why this exists

Ghost jobs don't just waste time. They create false hope, distort job market signals, and make an already stressful process harder. This tool is a small act of transparency. If it saves one person from tailoring a cover letter for a job that was never real, it's done its job.

**⭐ Star the repo if you find it useful — it helps others discover it.**
