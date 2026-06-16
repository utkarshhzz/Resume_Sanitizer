# Resume Sanitizer API 🕵️‍♂️🛡️

A production-ready microservice built with **FastAPI** that automatically detects and permanently redacts Personally Identifiable Information (PII) from PDF resumes using a high-accuracy 3-layer hybrid engine.

**Use Case**: Acts as a bridge between recruitment agencies and companies — resumes arrive clean with no way to contact candidates directly.

## 🚀 Architecture

```
PDF Upload → Parser (Text Extraction + OCR Fallback) → 3-Layer PII Analyzer → Redactor → Clean PDF
```

- **Layer 1 (Regex)**: Zero-cost, ~100% precision pattern matching for structured PII:
  - Email addresses, phone numbers (Indian + International)
  - LinkedIn, GitHub, Twitter, Instagram, Facebook, Telegram URLs
  - PAN cards, Aadhaar numbers, IFSC codes, Voter IDs, Passports
  - Personal portfolio/website URLs (catch-all)
  
- **Layer 2 (NLP NER)**: Contextual named entity recognition via spaCy + Microsoft Presidio for unstructured PII (names, locations).

- **Layer 3 (Heuristics)**: Smart structural rules:
  - "Largest font at the top = candidate's name" (multi-span aware)
  - Label-triggered detection: `Phone:`, `Email:`, `GitHub:`, `LinkedIn:`, `DOB:`, etc.
  - Section-aware confidence boosting (CONTACT section gets +0.10 boost, EXPERIENCE section gets -0.15 for PERSON entities to avoid false positives on company names)

- **OCR Fallback**: Automatically detects scanned (image-only) PDFs and falls back to Tesseract OCR.

- **Deep Redaction**: 
  - White-fill redaction (invisible — looks like info was never there)
  - Physically removes text from PDF binary structure (not just a visual overlay)
  - Purges ALL clickable hyperlinks (LinkedIn, GitHub, email mailto:, personal sites)
  - Scrubs document metadata (Author, Title, Subject, Keywords, Producer, Creator)
  - Removes embedded XML metadata streams

## 📦 Quickstart (Docker)

The fastest way to run this locally with the full stack (App + Redis + Prometheus + Grafana):

```bash
docker-compose up --build
```
> The API will be available at `http://localhost:8080`

### Local Development (without Docker)

```bash
# 1. Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows

# 2. Install dependencies
pip install -r requirements.txt
python -m spacy download en_core_web_lg

# 3. Run
uvicorn resume_sanitizer.main:app --reload --port 8000
```

## 🕹️ API Reference

### 1. `POST /api/v1/sanitize`
Upload a PDF. Receive a fully sanitized PDF back (white-space redaction).

```bash
curl -X POST "http://localhost:8000/api/v1/sanitize?return_metadata=true" \
  -H "accept: application/pdf" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@my_resume.pdf" \
  --output sanitized.pdf
```

**Query Parameters:**
| Parameter | Type | Default | Description |
|---|---|---|---|
| `return_metadata` | bool | false | Include PII entity metadata in response headers |
| `min_confidence` | float | 0.55 | Minimum detection confidence (0.0–1.0) |
| `redact_types` | string | null | Comma-separated list of entity types to redact (e.g., `EMAIL_ADDRESS,PHONE_NUMBER`) |

**Response Headers:**
- `X-PII-Count`: Total number of entities redacted
- `X-OCR-Used`: Whether OCR fallback was triggered
- `X-Cache`: `HIT` or `MISS`
- `X-Processing-Time-Ms`: Pipeline execution time
- `X-Redaction-Manifest` (when `return_metadata=true`): JSON array of redacted entities with type, layer, score, and page

### 2. `POST /api/v1/analyze-only`
Finds PII and returns a JSON list with details, but does **NOT** redact the PDF. Great for debugging and confidence tuning.

```bash
curl -X POST "http://localhost:8000/api/v1/analyze-only" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@my_resume.pdf"
```

### 3. `POST /api/v1/batch`
Process up to 10 PDFs concurrently. Returns metadata + base64-encoded sanitized PDFs.

### 4. `GET /health` & `GET /api/v1/entities`
Health check and list of all supported PII detection patterns.

## ⚙️ Environment Variables
Check `.env.example` for all configurable limits (Rate Limiting, Cache TTLs, OCR settings, etc.).

## 📊 Monitoring
- **Prometheus**: `http://localhost:9090` — Metrics scraping
- **Grafana**: `http://localhost:3000` — Dashboard (admin/admin)
- **Metrics endpoint**: `http://localhost:8000/metrics`

## 🧪 Testing

```bash
python -m pytest tests/ -v --tb=short
```
