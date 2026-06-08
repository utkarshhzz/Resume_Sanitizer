# Resume Sanitizer API 🕵️‍♂️🛡️

A production-ready microservice built with **FastAPI** that automatically detects and permanently redacts Personally Identifiable Information (PII) from PDFs using a high-accuracy 3-layer hybrid engine.

## 🚀 Architecture
- **Layer 1 (Regex)**: Zero-cost, 100% precision regex pattern matching (Emails, Phone numbers, PAN cards, Links, etc.).
- **Layer 2 (NLP NER)**: Contextual named entity recognition via SPAcy + Microsoft Presidio (Names, Locations, Orgs).
- **Layer 3 (Heuristics)**: Structural rules (e.g., "The largest font at the top is the name") and regex anchors (e.g., `DOB: <catch_all>`).
- **OCR Fallback**: Automatically senses scanned (image) PDFs and falls back to Tesseract OCR to find physical coordinates.
- **Deep Redaction**: Rips out the specific PDF text commands and erases binary metadata XML paths so hackers cannot recover removed data.

## 📦 Quickstart (Docker)

The fastest way to run this locally with the full stack (App + Redis + Prometheus + Grafana):

```bash
docker-compose up --build
```
> The API will be available at `http://localhost:8000`

## 🕹️ API Reference

### 1. `POST /api/v1/sanitize`
Upload a PDF. Receive a fully redacted PDF binary back.

```bash
curl -X POST "http://localhost:8000/api/v1/sanitize?return_metadata=true" \
  -H "accept: application/pdf" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@my_resume.pdf" \
  --output sanitized.pdf
```
**Special Headers in Response:**
- `X-PII-Count`: Total number of entities blacked out.
- `X-OCR-Used`: Were image-to-text algorithms triggered?
- `X-Redaction-Manifest`: Unlocked via `return_metadata=true`; proves *what* was deleted safely.

### 2. `POST /api/v1/analyze-only`
Finds PII and gives you a JSON list with bounding boxes, but does NOT redact the PDF. Great for debugging.

```bash
curl -X POST "http://localhost:8000/api/v1/analyze-only" \
  -H "accept: application/json" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@my_resume.pdf"
```

### 3. `GET /health` & `GET /api/v1/entities`
Returns standard health data and a list of all currently supported PII tracking patterns.

## ⚙️ Environment Variables
Check `.env.example` for all configurable limits (Rate Limiting, Cache TTLs, Maximum Megabytes).
