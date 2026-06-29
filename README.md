# Resume Sanitizer

A production-grade microservice that removes personally identifiable information (PII) from resumes. Upload a PDF, get back a clean version with names, emails, phone numbers, social links, and other sensitive data permanently erased — as if the info was never there.

## What Gets Removed

| Category | Examples |
|---|---|
| **Contact Info** | Email, phone numbers (Indian/international), LinkedIn, GitHub |
| **Social Media** | Twitter/X, Instagram, Facebook, Telegram, Medium, Behance, Dribbble |
| **Identity Docs** | PAN card, Aadhaar, Voter ID, Passport, SSN |
| **Financial** | Bank account numbers, IFSC codes |
| **URLs** | Personal websites, portfolios, blogs |
| **Metadata** | PDF Author, Title, Subject, XML metadata |
| **Hyperlinks** | All clickable links are severed from the PDF |

## What Stays

- Work experience, education, skills, projects, certifications
- Company names, technologies, tools
- School/college addresses
- Resume formatting and layout

## Quick Start (Docker)

```bash
# Build and run everything
docker compose up --build

# Service available at:
# API:        http://localhost:8000
# Swagger UI: http://localhost:8000/docs
# Health:     http://localhost:8000/health
# Metrics:    http://localhost:9090 (Prometheus)
# Dashboard:  http://localhost:3000 (Grafana, admin/admin)
```

## Quick Start (Local Dev)

```bash
python -m venv venv
.\venv\Scripts\activate        # Windows
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# Run
python -m uvicorn resume_sanitizer.main:app --reload --port 8000
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/v1/sanitize` | Upload PDF → get sanitized PDF back |
| `POST` | `/api/v1/analyze-only` | Dry run — returns detected PII as JSON |
| `POST` | `/api/v1/batch` | Process up to 10 PDFs concurrently |
| `GET` | `/api/v1/entities` | List all detectable PII types |
| `GET` | `/health` | Health check for load balancers |

### Sanitize Example

```bash
curl -X POST "http://localhost:8000/api/v1/sanitize" \
  -F "file=@resume.pdf" \
  -o sanitized_resume.pdf
```

### Response Headers

| Header | Description |
|---|---|
| `X-PII-Count` | Number of PII entities detected |
| `X-OCR-Used` | Whether OCR was needed (scanned PDF) |
| `X-Cache` | `HIT` if result was cached |
| `X-Processing-Time-Ms` | Total processing time |

## Architecture

```
PDF Upload → Parser (PyMuPDF/Tesseract OCR)
           → Analyzer (Regex + spaCy NER + Heuristics)
           → Redactor (Physical text removal + link severing)
           → Clean PDF
```

### Detection Layers

1. **Regex** — High-precision patterns for emails, phones, URLs, PAN, Aadhaar, etc.
2. **NLP (spaCy)** — Named entity recognition for person names
3. **Heuristics** — Largest font = name, label triggers ("Phone: xxx"), section-aware confidence boosting

## Testing

```bash
python -m pytest tests/ -v
```

## Tech Stack

- **FastAPI** + **Gunicorn** — async API server
- **PyMuPDF** — PDF parsing and physical redaction
- **Tesseract OCR** — scanned PDF fallback
- **Presidio + spaCy** — PII detection engine
- **Redis** — response caching
- **Prometheus + Grafana** — metrics and monitoring
