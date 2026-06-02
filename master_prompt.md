
---

## ████ ROLE & CONTEXT ████

You are a Principal Software Engineer specializing in Python 3.11+, FastAPI, computer vision, NLP, and cloud-native microservice architecture. You are building a production-ready **Resume Sanitization Microservice** for a B2B SaaS client that processes resumes at scale (target: 100 K+ resumes/day) before they enter an ATS or AI screening pipeline.

The service must detect and permanently redact all Personally Identifiable Information (PII) from uploaded PDF resumes — including scanned image-based PDFs — using a **3-layer hybrid PII engine** that runs entirely **in-process with zero per-request LLM token costs**.

The architecture diagram reference:
- FastAPI load-balanced gateway → PDF extraction (PyMuPDF + OCR fallback) → 3-layer PII detection → coordinate-based redaction → sanitized PDF streamed back
- Layer 1: Regex (~99% structured PII, free)
- Layer 2: Microsoft Presidio + spaCy NER (~87% unstructured, local)
- Layer 3: Context-aware heuristics (+5–10% accuracy boost)

---

## ████ PROJECT STRUCTURE ████

Generate every file listed below. Do not skip any. Do not hallucinate imports or libraries not listed in `requirements.txt`.

```
resume_sanitizer/
├── main.py                   # FastAPI gateway + lifespan + middleware
├── parser.py                 # PDF text extraction + OCR fallback
├── analyzer.py               # 3-layer PII detection engine
├── redactor.py               # Coordinate-based permanent redaction
├── cache.py                  # SHA-256 in-memory + Redis dedup layer
├── config.py                 # Pydantic v2 Settings (env-based)
├── models.py                 # Pydantic request/response schemas
├── middleware.py             # Rate limiting, request-ID injection, logging
├── metrics.py                # Prometheus metrics instrumentation
├── exceptions.py             # Custom exception hierarchy
├── utils.py                  # Shared utilities (hashing, timing, bbox math)
├── tests/
│   ├── conftest.py           # Pytest fixtures (sample PDFs, mock engines)
│   ├── test_parser.py
│   ├── test_analyzer.py
│   ├── test_redactor.py
│   └── test_api.py           # Full integration tests via httpx AsyncClient
├── Dockerfile
├── docker-compose.yml        # App + Redis + Prometheus + Grafana
├── .env.example
├── requirements.txt
└── README.md
```

---

## ████ MODULE 1 — `config.py` (Build First) ████

Use **Pydantic v2 `BaseSettings`** with `model_config = SettingsConfigDict(env_file=".env")`.

Define these settings fields with types and defaults:

```python
# Environment
APP_ENV: str = "production"            # "development" | "staging" | "production"
APP_VERSION: str = "1.0.0"
LOG_LEVEL: str = "INFO"

# API
API_PREFIX: str = "/api/v1"
MAX_UPLOAD_SIZE_MB: int = 20           # Reject files larger than this
ALLOWED_CONTENT_TYPES: list[str] = ["application/pdf"]
REQUEST_TIMEOUT_SECONDS: int = 30

# OCR
OCR_CHAR_THRESHOLD: int = 50           # Min chars before triggering OCR fallback
OCR_DPI: int = 300                     # DPI for pdf2image conversion
OCR_LANGUAGE: str = "eng"             # Tesseract language
OCR_CONFIDENCE_THRESHOLD: int = 40    # Min Tesseract word confidence to include

# Presidio / NLP
SPACY_MODEL: str = "en_core_web_lg"
USE_ONNX_NER: bool = False            # Toggle ONNX model vs spaCy
ONNX_MODEL_PATH: str = "models/ner_model.onnx"

# Cache
CACHE_BACKEND: str = "memory"         # "memory" | "redis"
REDIS_URL: str = "redis://localhost:6379/0"
CACHE_TTL_SECONDS: int = 3600         # 1 hour

# Rate Limiting
RATE_LIMIT_REQUESTS: int = 100
RATE_LIMIT_WINDOW_SECONDS: int = 60

# Redaction
REDACTION_FILL_COLOR: tuple[float, float, float] = (0.0, 0.0, 0.0)  # RGB black
REDACTION_PADDING_PX: int = 2         # Extra pixels around each bbox
```

Expose a module-level `settings = Settings()` singleton.

---

## ████ MODULE 2 — `exceptions.py` ████

Define a clean exception hierarchy:

```python
class SanitizerBaseError(Exception): ...
class FileTooLargeError(SanitizerBaseError): ...
class InvalidFileTypeError(SanitizerBaseError): ...
class PDFCorruptedError(SanitizerBaseError): ...
class OCREngineError(SanitizerBaseError): ...
class PIIAnalysisError(SanitizerBaseError): ...
class RedactionError(SanitizerBaseError): ...
class CacheError(SanitizerBaseError): ...
```

Each must carry: `message: str`, `detail: str | None = None`, `status_code: int`.

---

## ████ MODULE 3 — `models.py` ████

All models use **Pydantic v2** with `model_config = ConfigDict(frozen=True)`.

### Request Schema
```python
class SanitizeRequest(BaseModel):
    # Injected programmatically — not a form field
    file_hash: str
    filename: str
    content_type: str
    file_size_bytes: int
```

### Response Schema
```python
class PIIEntity(BaseModel):
    entity_type: str          # e.g. "EMAIL_ADDRESS", "PERSON", "PHONE_NUMBER"
    text: str                 # Original (pre-redaction) matched text
    score: float              # Presidio confidence 0.0–1.0
    page: int                 # 1-indexed page number
    detection_layer: str      # "regex" | "presidio_ner" | "heuristic" | "ocr_context"
    start: int                # Character offset in page text
    end: int                  # Character offset in page text

class SanitizeResponse(BaseModel):
    request_id: str
    filename: str
    file_hash: str
    cache_hit: bool
    pages_processed: int
    ocr_used: bool
    pii_entities_found: int
    entities: list[PIIEntity]
    processing_time_ms: float
    sanitized_pdf_size_bytes: int
```

### Internal DTOs
```python
class PageTextBlock(BaseModel):
    page_number: int          # 1-indexed
    text: str                 # Full page text concat
    words: list[WordBlock]    # Word-level detail for OCR path

class WordBlock(BaseModel):
    text: str
    x0: float; y0: float; x1: float; y1: float
    page_number: int
    confidence: int           # Tesseract confidence 0–100; -1 for digital path
    font_size: float          # Points; -1 for OCR path
    is_bold: bool

class RedactionTarget(BaseModel):
    page_number: int
    entity_type: str
    original_text: str
    rects: list[tuple[float, float, float, float]]   # (x0, y0, x1, y1) per rect
    source: str               # "digital" | "ocr"
```

---

## ████ MODULE 4 — `utils.py` ████

Implement these utility functions with full type hints and docstrings:

```python
def compute_sha256(buffer: bytes) -> str:
    """SHA-256 hex digest of raw bytes."""

def timeit_async(func):
    """Async decorator that injects elapsed_ms into the function return via a wrapper tuple."""

def expand_rect(rect: tuple, padding: int, page_width: float, page_height: float) -> tuple:
    """Expand (x0,y0,x1,y1) by padding pixels, clamped to page boundaries."""

def merge_overlapping_rects(rects: list[tuple]) -> list[tuple]:
    """
    Merge horizontally overlapping/adjacent redaction rectangles on the same line
    to avoid fragmented black boxes for multi-word PII spans.
    Uses a sweep-line algorithm: sort by x0, merge if x0[i] <= x1[i-1] + threshold.
    """

def normalize_text_for_search(text: str) -> str:
    """Normalize unicode, collapse whitespace for reliable page.search_for() matching."""

def chunk_list(lst: list, size: int) -> Generator:
    """Yield successive chunks of size `size` from list."""
```

---

## ████ MODULE 5 — `parser.py` ████

### Imports
```python
import fitz  # PyMuPDF
import io, logging
from pdf2image import convert_from_bytes
import pytesseract
from pytesseract import Output
from PIL import Image
```

### Function: `extract_text_digital(pdf_bytes: bytes) -> tuple[fitz.Document, list[PageTextBlock]]`

- Open the PDF **from bytes** using `fitz.open(stream=pdf_bytes, filetype="pdf")`.
- For each page: call `page.get_text("words")` to get word-level blocks `(x0, y0, x1, y1, word, block_no, line_no, word_no)`.
- Also call `page.get_text("dict")` to extract font sizes per span for heuristic analysis.
- Build a `PageTextBlock` per page, populating `WordBlock` entries with coordinates and `font_size` from the dict pass.
- Return the `fitz.Document` handle (do NOT close it — caller owns lifetime) and the block list.
- **Must not write any temp files.** All operations on `io.BytesIO`.

### Function: `needs_ocr(blocks: list[PageTextBlock]) -> bool`

- Return `True` if the total character count across all blocks is below `settings.OCR_CHAR_THRESHOLD`.

### Function: `extract_text_ocr(pdf_bytes: bytes) -> list[PageTextBlock]`

- Convert pages to PIL Images via `convert_from_bytes(pdf_bytes, dpi=settings.OCR_DPI)`.
- For each image run `pytesseract.image_to_data(img, output_type=Output.DICT, lang=settings.OCR_LANGUAGE)`.
- Filter words where `conf >= settings.OCR_CONFIDENCE_THRESHOLD` and `text.strip() != ""`.
- **Critical**: Tesseract returns pixel coordinates for the given DPI. Convert pixel coords back to PDF points: `pt = px * 72 / DPI`. This ensures the redaction rects align with the actual PDF page coordinate space.
- Reconstruct full-page text by joining filtered words with spaces (preserve line breaks using `block_num` and `line_num` from Tesseract output).
- Return a `list[PageTextBlock]` with `confidence` populated per word.

### Function: `extract(pdf_bytes: bytes) -> tuple[fitz.Document | None, list[PageTextBlock], bool]`

- Orchestrator: calls `extract_text_digital`, checks `needs_ocr`, conditionally calls `extract_text_ocr`.
- Returns `(doc, blocks, ocr_used)`.
- If OCR path is taken, `doc` is still the `fitz.Document` opened from bytes (needed for redaction geometry even on scanned PDFs).
- Wrap in `try/except fitz.FileDataError` → raise `PDFCorruptedError`.

---

## ████ MODULE 6 — `analyzer.py` ████

### Setup: `build_analyzer_engine() -> AnalyzerEngine`

This is the core. Call once at startup via FastAPI lifespan.

**Step A — Custom Regex Recognizers**

Create a `PatternRecognizer` for each of the following. Each must have `supported_entity` (capitalized snake-case string), a list of `Pattern` objects (with `name`, `regex`, `score`), and `context` list for context-boosting:

| Entity Type | Regex | Score |
|---|---|---|
| `EMAIL_ADDRESS` | `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}` | 0.95 |
| `PHONE_NUMBER` | `(\+?91[\-\s]?)?[6-9]\d{9}` (Indian mobile) + `(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}` (intl) | 0.90 |
| `LINKEDIN_URL` | `(https?://)?(www\.)?linkedin\.com/(in\|pub\|profile)/[A-Za-z0-9\-_%]+` | 0.98 |
| `GITHUB_URL` | `(https?://)?(www\.)?github\.com/[A-Za-z0-9\-_.]+` | 0.98 |
| `PAN_CARD` | `[A-Z]{5}[0-9]{4}[A-Z]` | 0.95 |
| `AADHAAR_NUMBER` | `\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b` | 0.95 |
| `PINCODE_IN` | `\b[1-9][0-9]{5}\b` with context words `["pincode", "pin", "postal"]` | 0.75 |
| `VOTER_ID_IN` | `[A-Z]{3}[0-9]{7}` | 0.88 |
| `PASSPORT_IN` | `[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]` | 0.90 |
| `IP_ADDRESS` | `\b(?:\d{1,3}\.){3}\d{1,3}\b` | 0.85 |
| `DATE_OF_BIRTH` | `\b(0?[1-9]\|[12]\d\|3[01])[\/\-](0?[1-9]\|1[0-2])[\/\-](19\|20)\d{2}\b` with context `["dob", "date of birth", "born"]` | 0.80 |
| `BANK_ACCOUNT_IN` | `\b\d{9,18}\b` with context `["account", "acc no", "bank"]` | 0.70 |
| `IFSC_CODE` | `[A-Z]{4}0[A-Z0-9]{6}` | 0.95 |

**Step B — Presidio NLP Engine Setup**

Use `NlpEngineProvider` to build the NLP engine. Provide TWO code paths controlled by `settings.USE_ONNX_NER`:

*Path A (default): spaCy NLP Engine*
```python
configuration = {
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": settings.SPACY_MODEL}],
}
provider = NlpEngineProvider(nlp_configuration=configuration)
nlp_engine = provider.create_engine()
```

*Path B (ONNX — blueprint, not fully wired):*
```python
# Blueprint: Use transformers NLP engine pointing to ONNX runtime model
# This achieves 97-98% accuracy at zero per-inference cost
# 1. Load model: from optimum.onnxruntime import ORTModelForTokenClassification
# 2. Load tokenizer: AutoTokenizer.from_pretrained(settings.ONNX_MODEL_PATH)
# 3. Build a TransformersNlpEngine subclass that wraps the ONNX session
# 4. Register with NlpEngineProvider
# Wire up when settings.USE_ONNX_NER is True — raises NotImplementedError if model path missing
```

Build the `AnalyzerEngine` with:
```python
analyzer = AnalyzerEngine(
    nlp_engine=nlp_engine,
    supported_languages=["en"],
)
# Add all custom recognizers to analyzer.registry
```

### Function: `detect_largest_font_name(doc: fitz.Document) -> PIIEntity | None`

**This is the Layer 3 structural heuristic.** On page 0 of the document:

1. Parse `page.get_text("dict")` → iterate `blocks → lines → spans`.
2. Find the span with the **maximum `size` (font size)** that:
   - Is on the first half of the page (y-coordinate < page height / 2)
   - Has `len(span["text"].strip()) > 3`
   - Does not look like a section header keyword (exclude: "resume", "curriculum vitae", "cv", "profile", "summary", "experience", "education", "skills")
3. Flag that span's text as a `PERSON` entity with `score=0.72`, `detection_layer="heuristic"`.
4. Return `None` if no qualifying span found.

### Function: `detect_label_triggered_pii(blocks: list[PageTextBlock]) -> list[PIIEntity]`

**Layer 3 label-trigger heuristics.** Scan each line of the full text for patterns like:

- `"Phone:"`, `"Tel:"`, `"Mobile:"`, `"Cell:"` → capture the token(s) immediately after as `PHONE_NUMBER` with `score=0.85`
- `"Email:"`, `"E-mail:"` → capture token after as `EMAIL_ADDRESS` with `score=0.85`
- `"Address:"`, `"Location:"`, `"City:"` → capture remainder of line as `LOCATION` with `score=0.75`
- `"GitHub:"`, `"Git:"` → capture URL after as `GITHUB_URL` with `score=0.90`
- `"LinkedIn:"` → capture URL after as `LINKEDIN_URL` with `score=0.90`
- `"DOB:"`, `"Date of Birth:"` → capture as `DATE_OF_BIRTH` with `score=0.88`

Use line-by-line parsing. Return character offsets relative to the full page text string.

### Function: `analyze(doc: fitz.Document, blocks: list[PageTextBlock], ocr_used: bool) -> list[PIIEntity]`

Master analysis orchestrator:

1. **Layer 1 + 2**: For each `PageTextBlock`, run `analyzer.analyze(text=block.text, language="en", entities=[...all entity types...])`.
2. **Layer 3**: Run `detect_largest_font_name(doc)` and `detect_label_triggered_pii(blocks)` and append results.
3. **Deduplication**: Remove overlapping detections using offset ranges — keep the higher-score entity. Overlapping means `start_a < end_b and start_b < end_a` on the same page.
4. Filter results to `score >= 0.55` minimum threshold.
5. Assign `detection_layer` based on recognizer name (regex pattern recognizers → `"regex"`, NER → `"presidio_ner"`, heuristics → `"heuristic"`).
6. Return flattened, deduplicated list of `PIIEntity`.

---

## ████ MODULE 7 — `redactor.py` ████

### Function: `build_redaction_targets(doc: fitz.Document, entities: list[PIIEntity], blocks: list[PageTextBlock], ocr_used: bool) -> list[RedactionTarget]`

**Digital path** (for each entity on a digital page):
- Call `page.search_for(normalize_text_for_search(entity.text), quads=True)`.
- `search_for` returns a list of `fitz.Quad` objects. Convert each to `fitz.Rect` via `.rect`.
- Apply `expand_rect()` with `settings.REDACTION_PADDING_PX`.
- If `search_for` returns 0 results (text normalized differently), attempt a fuzzy fallback: search for first 15 chars of the entity text.

**OCR path** (for each entity on an OCR page):
- The entity `start`/`end` offsets map into the reconstructed page text string.
- Walk through the `WordBlock` list for that page. Track a running character offset.
- Collect `WordBlock`s whose character range overlaps `[entity.start, entity.end]`.
- Their `(x0, y0, x1, y1)` fields are already in PDF-point space (converted in `parser.py`).
- Apply `expand_rect()`.

After collecting all rects for an entity, call `merge_overlapping_rects()` to consolidate.

Return a `list[RedactionTarget]` — one per unique entity occurrence (multiple rects possible per target).

### Function: `apply_redactions(doc: fitz.Document, targets: list[RedactionTarget]) -> bytes`

- Group targets by `page_number`.
- For each page:
  - For each rect in each target: call `page.add_redact_annot(rect, fill=settings.REDACTION_FILL_COLOR)`.
  - Call `page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)` — this **permanently removes** the underlying text from the PDF structure (not just a visual overlay). Specify `images=fitz.PDF_REDACT_IMAGE_NONE` to preserve embedded images while redacting text.
- Scrub document-level metadata (author, title, subject, keywords, producer, creator) by calling `doc.set_metadata({})`.
- Remove embedded XML metadata streams: `doc.del_xml_metadata()`.
- Serialize to bytes: `buf = io.BytesIO(); doc.save(buf, garbage=4, deflate=True, clean=True); return buf.getvalue()`.
  - `garbage=4`: aggressive object tree compaction
  - `deflate=True`: compress streams
  - `clean=True`: remove orphaned objects
- Close `doc` after saving.

---

## ████ MODULE 8 — `cache.py` ████

Abstract base + two concrete implementations:

```python
class BaseCache(ABC):
    async def get(self, key: str) -> bytes | None: ...
    async def set(self, key: str, value: bytes, ttl: int) -> None: ...

class InMemoryCache(BaseCache):
    # Use a dict with (value, expire_at) tuples. Evict expired on get().
    # Thread-safe via asyncio.Lock.
    # Max 500 entries — LRU eviction using collections.OrderedDict.

class RedisCache(BaseCache):
    # Use aioredis (redis.asyncio). Connect lazily on first use.
    # Serialize/deserialize bytes directly (no JSON encoding).
    # Graceful degradation: if Redis unreachable, log warning and return None from get().
```

Factory function:
```python
def get_cache() -> BaseCache:
    if settings.CACHE_BACKEND == "redis":
        return RedisCache(settings.REDIS_URL)
    return InMemoryCache()
```

---

## ████ MODULE 9 — `middleware.py` ████

### `RequestIDMiddleware(BaseHTTPMiddleware)`
- Generate `uuid4` request ID per request.
- Inject into request state: `request.state.request_id = rid`.
- Add response header: `X-Request-ID: {rid}`.

### `LoggingMiddleware(BaseHTTPMiddleware)`
- Structured JSON log on each request/response:
  ```json
  {"event": "request", "method": "POST", "path": "/api/v1/sanitize", "request_id": "...", "ts": "..."}
  {"event": "response", "status": 200, "duration_ms": 342.1, "request_id": "..."}
  ```
- Use Python's `logging` module with a `JSONFormatter`.

### `RateLimitMiddleware(BaseHTTPMiddleware)`
- In-memory sliding window per client IP.
- `settings.RATE_LIMIT_REQUESTS` requests per `settings.RATE_LIMIT_WINDOW_SECONDS`.
- Return `HTTP 429` with `Retry-After` header when exceeded.
- Use `asyncio.Lock` for thread safety.

### `FileSizeMiddleware(BaseHTTPMiddleware)`
- Read `Content-Length` header; if > `settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024`, return `HTTP 413` immediately before the route handler runs.

---

## ████ MODULE 10 — `metrics.py` ████

Use the `prometheus-client` library.

Define these metrics at module level:

```python
REQUEST_COUNT = Counter("sanitizer_requests_total", "Total sanitize requests", ["status"])
REQUEST_LATENCY = Histogram("sanitizer_request_duration_seconds", "Request duration", buckets=[.1,.25,.5,1,2,5,10])
PII_ENTITIES_FOUND = Histogram("sanitizer_pii_entities_per_document", "PII count per doc", buckets=[0,1,5,10,20,50,100])
OCR_USAGE = Counter("sanitizer_ocr_fallback_total", "Times OCR fallback triggered")
CACHE_HITS = Counter("sanitizer_cache_hits_total", "Cache hit count")
CACHE_MISSES = Counter("sanitizer_cache_misses_total", "Cache miss count")
FILE_SIZE_BYTES = Histogram("sanitizer_file_size_bytes", "Input PDF size", buckets=[1e4,1e5,5e5,1e6,5e6,2e7])
```

Expose `/metrics` endpoint using `make_asgi_app()` from prometheus-client (mount as sub-app).

---

## ████ MODULE 11 — `main.py` ████

### Lifespan Context Manager

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Loading spaCy model...")
    app.state.analyzer = build_analyzer_engine()  # warm up
    app.state.cache = get_cache()
    logger.info("Analyzer engine ready.")
    yield
    # Shutdown
    logger.info("Shutting down sanitizer service.")
```

### FastAPI App Initialization

```python
app = FastAPI(
    title="Resume Sanitizer API",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)
```

Add middlewares in this order (outermost first):
1. `RequestIDMiddleware`
2. `LoggingMiddleware`
3. `FileSizeMiddleware`
4. `RateLimitMiddleware`
5. `CORSMiddleware` (allow origins from env var `CORS_ORIGINS`, default `["*"]`)

Mount Prometheus metrics app at `/metrics`.

### Endpoints

**`GET /health`**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "environment": "production",
  "analyzer_ready": true,
  "cache_backend": "redis"
}
```

**`GET /api/v1/entities`**
Return the list of all entity types the engine can detect (for API consumers to know what's redacted).

**`POST /api/v1/sanitize`** ← PRIMARY ENDPOINT

Full implementation:

```python
@router.post("/sanitize", response_class=StreamingResponse)
async def sanitize_resume(
    request: Request,
    file: UploadFile = File(...),
    return_metadata: bool = Query(False, description="Include PII entity metadata in response headers"),
    min_confidence: float = Query(0.55, ge=0.0, le=1.0, description="Minimum Presidio confidence score"),
) -> StreamingResponse:
```

Implementation steps inside the endpoint (in order):

1. **Validate**: Check `file.content_type` is `application/pdf`. Raise `HTTP 415` if not.
2. **Read buffer**: `pdf_bytes = await file.read()` into memory. Do NOT use temp files.
3. **Hash**: `file_hash = compute_sha256(pdf_bytes)` using `utils.compute_sha256`.
4. **Cache lookup**: `cached = await request.app.state.cache.get(file_hash)`. If hit: increment `CACHE_HITS`, stream cached bytes directly with correct headers, return immediately.
5. **Increment miss counter**: `CACHE_MISSES.inc()`.
6. **Extract**: Call `parser.extract(pdf_bytes)` → `(doc, blocks, ocr_used)`.
7. **Analyze**: Call `analyzer.analyze(doc, blocks, ocr_used, min_confidence)` → `entities`.
8. **Redact**: Call `redactor.build_redaction_targets(doc, entities, blocks, ocr_used)` → `targets`. Then `redactor.apply_redactions(doc, targets)` → `sanitized_bytes`.
9. **Cache store**: `await request.app.state.cache.set(file_hash, sanitized_bytes, settings.CACHE_TTL_SECONDS)`.
10. **Metrics**: Update all Prometheus counters/histograms.
11. **Response headers**: Always include:
    - `X-Request-ID`: from `request.state.request_id`
    - `X-PII-Count`: number of entities found
    - `X-OCR-Used`: `"true"` or `"false"`
    - `X-Cache`: `"MISS"`
    - `X-Processing-Time-Ms`: elapsed ms
    - If `return_metadata=True`: `X-PII-Entities`: JSON-encoded list of entity types found
12. **Stream**: Return `StreamingResponse` with:
    ```python
    StreamingResponse(
        content=io.BytesIO(sanitized_bytes),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="sanitized_{file.filename}"',
            ...
        }
    )
    ```

**`POST /api/v1/analyze-only`** (dry-run, no redaction)

Same pipeline as `/sanitize` but skip the redaction step. Return a JSON body with the full `SanitizeResponse` schema including all detected `PIIEntity` objects. Useful for auditing and confidence tuning. Do NOT cache dry-run results.

**`POST /api/v1/batch`** (async batch endpoint)

Accept a list of up to 10 files via `List[UploadFile]`. Process each concurrently using `asyncio.gather`. Return a list of `SanitizeResponse` objects (metadata only). Sanitized PDFs are base64-encoded in the response. Enforce `MAX_UPLOAD_SIZE_MB` per-file.

### Error Handlers

Register handlers for:
- `SanitizerBaseError` → structured JSON `{"error": type, "message": ..., "request_id": ...}` at the appropriate HTTP status
- `RequestValidationError` → `HTTP 422` with field-level detail
- `Exception` (catch-all) → `HTTP 500` with request ID, log full traceback

---

## ████ MODULE 12 — `tests/` ████

### `conftest.py`
- Fixture `sample_digital_pdf`: Create a minimal in-memory PDF with `fitz.open()` containing known PII text (name, email, phone, LinkedIn URL, Aadhaar number).
- Fixture `sample_scanned_pdf`: A single-page PDF whose text layer is empty (simulating a scanned doc).
- Fixture `async_client`: `AsyncClient(app=app, base_url="http://test")` via `httpx`.
- Fixture `mock_analyzer`: Patch `build_analyzer_engine` to return a seeded engine with deterministic output.

### `test_parser.py`
- `test_digital_extraction_returns_text`: Assert text blocks non-empty for digital PDF.
- `test_ocr_fallback_triggered_for_scanned`: Assert `ocr_used=True` for scanned PDF.
- `test_ocr_coordinate_conversion`: Assert bbox coords are in valid PDF point range.
- `test_corrupt_pdf_raises`: Assert `PDFCorruptedError` on bad bytes.

### `test_analyzer.py`
- `test_email_regex_detection`
- `test_indian_phone_detection`
- `test_linkedin_url_detection`
- `test_github_url_detection`
- `test_pan_card_detection`
- `test_aadhaar_detection`
- `test_largest_font_heuristic`
- `test_deduplication_removes_overlapping`

### `test_redactor.py`
- `test_redaction_removes_text_from_pdf`: After `apply_redactions`, extract text with fitz and assert PII strings are no longer present.
- `test_redaction_metadata_scrubbed`: Assert `doc.metadata` is empty dict after redaction.
- `test_ocr_path_bbox_mapping`

### `test_api.py`
- `test_sanitize_endpoint_200`
- `test_sanitize_returns_pdf_content_type`
- `test_sanitize_rejects_non_pdf`
- `test_sanitize_rejects_oversized_file`
- `test_cache_hit_on_second_request`: Second identical upload returns `X-Cache: HIT`.
- `test_analyze_only_returns_entities_json`
- `test_rate_limit_429`
- `test_health_endpoint`

---

## ████ MODULE 13 — `Dockerfile` ████

```dockerfile
FROM python:3.11-slim-bookworm

# Install system dependencies for PyMuPDF, Tesseract, pdf2image, spaCy
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    poppler-utils \
    libmupdf-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache optimization)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download spaCy model (baked into image for zero cold-start delay)
RUN python -m spacy download en_core_web_lg

COPY . .

# Non-root user for security
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8000

# Preload models on startup with --preload
CMD ["gunicorn", "main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "60", \
     "--preload", \
     "--access-logfile", "-"]
```

---

## ████ MODULE 14 — `docker-compose.yml` ████

```yaml
version: "3.9"
services:
  sanitizer:
    build: .
    ports: ["8000:8000"]
    environment:
      - CACHE_BACKEND=redis
      - REDIS_URL=redis://redis:6379/0
      - APP_ENV=production
    depends_on: [redis]
    deploy:
      replicas: 2
      resources:
        limits: {cpus: "2.0", memory: "2G"}

  redis:
    image: redis:7-alpine
    ports: ["6379:6379"]
    command: redis-server --save 60 1 --loglevel warning

  prometheus:
    image: prom/prometheus:latest
    ports: ["9090:9090"]
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    ports: ["3000:3000"]
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

---

## ████ MODULE 15 — `requirements.txt` ████

```
# Core
fastapi==0.111.0
uvicorn[standard]==0.30.1
gunicorn==22.0.0
python-multipart==0.0.9
pydantic==2.7.4
pydantic-settings==2.3.4

# PDF
PyMuPDF==1.24.5

# OCR
pdf2image==1.17.0
pytesseract==0.3.13
Pillow==10.3.0

# PII Detection
presidio-analyzer==2.2.354
presidio-anonymizer==2.2.354
spacy==3.7.5
en_core_web_lg @ https://github.com/explosion/spacy-models/releases/download/en_core_web_lg-3.7.1/en_core_web_lg-3.7.1-py3-none-any.whl

# Cache
redis[hiredis]==5.0.6

# Metrics
prometheus-client==0.20.0

# Logging
python-json-logger==2.0.7

# Testing
pytest==8.2.2
pytest-asyncio==0.23.7
httpx==0.27.0
pytest-cov==5.0.0

# Dev / optional ONNX path
# optimum[onnxruntime]==1.20.0
# transformers==4.41.2
```

---

## ████ ADDITIONAL FEATURES TO IMPLEMENT ████

### Feature: Section-Aware PII Scoping
Parse resume sections (`EXPERIENCE`, `EDUCATION`, `SKILLS`, `CONTACT`, `SUMMARY`) from the text layout. Increase confidence scores for PII found in the `CONTACT` section by +0.10. This avoids false positives for company names/locations found in the EXPERIENCE section being misclassified as personal location PII.

Implement as `detect_resume_sections(blocks: list[PageTextBlock]) -> dict[str, tuple[int, int]]` returning section name → `(start_char_offset, end_char_offset)`.

### Feature: PII Audit Trail Header
When `return_metadata=True`, include a `X-Redaction-Manifest` response header containing a compact JSON array:
```json
[{"type":"EMAIL_ADDRESS","layer":"regex","confidence":0.95},{"type":"PERSON","layer":"heuristic","confidence":0.72}]
```
This allows downstream services to audit what was removed without the original content.

### Feature: Selective Redaction via Query Params
Add optional `redact_types` query param to `/sanitize` (comma-separated list of entity types). If provided, only redact those entity types. Default: redact all detected entities. Example: `?redact_types=EMAIL_ADDRESS,PHONE_NUMBER,AADHAAR_NUMBER`.

### Feature: Confidence Score Tunability
Accept `min_confidence: float = Query(0.55)` on both `/sanitize` and `/analyze-only`. Filter all entities below this threshold before redaction. Document the trade-off: lower = more aggressive (higher recall, lower precision); higher = more conservative.

### Feature: Structured Logging Correlation
Every log line must include `request_id`, `file_hash` (truncated to 8 chars for log brevity), and `env`. Use `python-json-logger` with a custom filter that injects these from `request.state`.

---

## ████ IMPLEMENTATION RULES ████

1. **Type hints everywhere.** Every function, parameter, and return value must have a complete type annotation. Use `from __future__ import annotations` at the top of every module.
2. **Docstrings.** Every public function must have a Google-style docstring with Args, Returns, Raises sections.
3. **No disk I/O.** All PDF operations must use `io.BytesIO` or in-memory byte buffers. No `open()`, no `tempfile`. This is a hard constraint.
4. **No global mutable state.** The analyzer engine and cache are initialized at startup via `lifespan` and stored in `app.state`. Never use module-level mutable singletons.
5. **Async all the way.** All I/O-bound operations (cache reads/writes, file reads) must be `async`. CPU-bound operations (PyMuPDF parsing, Presidio analysis) are synchronous but must be wrapped with `asyncio.run_in_executor(None, ...)` in the endpoint to avoid blocking the event loop.
6. **Error handling.** Every external call (fitz, Tesseract, Presidio) must be wrapped in try/except that raises the appropriate custom exception from `exceptions.py`.
7. **No hardcoded secrets.** All secrets and config via `settings` from `config.py`. No magic strings in business logic modules.
8. **Test coverage ≥ 80%.** All critical paths (digital extraction, OCR fallback, regex detection, redaction) must have unit tests.
9. **Immutable Pydantic models.** Use `ConfigDict(frozen=True)` on all DTOs to prevent mutation bugs in the pipeline.
10. **Generate `README.md`** with: architecture overview, quickstart (Docker), API reference (all endpoints with example curl commands), environment variable reference, and performance benchmarks table.

---

## ████ EXPECTED ACCURACY TARGETS ████

| Entity Type | Detection Layer | Expected Recall |
|---|---|---|
| Email addresses | Layer 1 (regex) | ~100% |
| Indian phone numbers | Layer 1 (regex) | ~99% |
| LinkedIn / GitHub URLs | Layer 1 (regex) | ~99% |
| PAN / Aadhaar / IFSC | Layer 1 (regex) | ~98% |
| Person names | Layer 2 (Presidio NER) + Layer 3 (heuristic) | ~88–94% |
| Location / city | Layer 2 (Presidio NER) | ~85% |
| Addresses | Layer 2 (Presidio NER) + Layer 3 (label trigger) | ~82% |
| **Overall composite** | **3-layer hybrid** | **92–97%** |

---