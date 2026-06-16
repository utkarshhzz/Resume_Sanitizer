from __future__ import annotations

import asyncio
import base64
import logging
import sys
import time
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, Request, UploadFile, File, Query
from fastapi.responses import Response, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from pythonjsonlogger import jsonlogger
from prometheus_client import make_asgi_app

from resume_sanitizer.config import settings
from resume_sanitizer.exceptions import SanitizerBaseError, InvalidFileTypeError
from resume_sanitizer.models import SanitizeResponse
from resume_sanitizer.utils import compute_sha256
from resume_sanitizer.cache import get_cache
from resume_sanitizer.parser import extract
from resume_sanitizer.analyzer import build_analyzer_engine, analyze, REGEX_DEFINITIONS
from resume_sanitizer.redactor import build_redaction_targets, apply_redactions
from resume_sanitizer import metrics
from resume_sanitizer.middleware import (
    RequestIDMiddleware,
    LoggingMiddleware,
    FileSizeMiddleware,
    RateLimitMiddleware
)

# --- LOGGING SETUP ---
logger = logging.getLogger()
logHandler = logging.StreamHandler(sys.stdout)
formatter = jsonlogger.JsonFormatter(
    fmt="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
logger.setLevel(settings.LOG_LEVEL)


# --- LIFESPAN (STARTUP/SHUTDOWN EVENT) ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing Resume Sanitizer Service...")
    
    # 1. Warm up the heavy ML Models once on startup
    logger.info("Loading analyzer engine (spaCy)...")
    app.state.analyzer = build_analyzer_engine()
    
    # 2. Connect to the Cache (Redis/In-Memory)
    logger.info("Initializing cache connection...")
    app.state.cache = get_cache()
    
    logger.info("Service is ready to rock!")
    yield
    
    logger.info("Shutting down service...")


# --- APP INITIALIZATION ---
app = FastAPI(
    title="Resume Sanitizer API",
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# --- MIDDLEWARE REGISTRATION (Order matters: outer to inner) ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=[
        "X-Request-ID", "X-PII-Count", "X-OCR-Used", "X-Cache",
        "X-Processing-Time-Ms", "X-Redaction-Manifest", "Content-Disposition",
    ],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(FileSizeMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(RequestIDMiddleware)

# Prometheus endpoint registration (Using the WSGI app exporter)
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


# --- EXCEPTION HANDLERS ---
@app.exception_handler(SanitizerBaseError)
async def sanitizer_exception_handler(request: Request, exc: SanitizerBaseError):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.__class__.__name__, "message": exc.message, "request_id": getattr(request.state, "request_id", "unknown")}
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": "ValidationError", "message": "Invalid request parameters", "details": exc.errors()}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled Exception: {exc}", exc_info=True)
    metrics.REQUEST_COUNT.labels(status="500").inc()
    return JSONResponse(
        status_code=500,
        content={"error": "InternalServerError", "message": "An unexpected error occurred", "request_id": getattr(request.state, "request_id", "unknown")}
    )


# --- ENDPOINTS ---

@app.get("/health")
async def health_check():
    """Simple health ping for load balancers."""
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "environment": settings.APP_ENV,
        "analyzer_ready": hasattr(app.state, "analyzer"),
        "cache_backend": settings.CACHE_BACKEND
    }


@app.get(f"{settings.API_PREFIX}/entities")
async def list_entities():
    """Lists all the PII types this engine is capable of detecting and purging."""
    custom_entities = [defn.entity for defn in REGEX_DEFINITIONS]
    nlp_entities = ["PERSON", "LOCATION", "ORG", "US_SSN", "UK_NHS"]
    return {"supported_entities": sorted(custom_entities + nlp_entities)}


async def process_pdf(request: Request, file_bytes: bytes, filename: str, min_confidence: float, redaction_mode: bool, redact_types: str | None = None) -> tuple[bytes | None, SanitizeResponse]:
    """
    Core business logic pipeline extracted into a helper for reuse across single/batch endpoints.
    Returns (sanitized_pdf_bytes, metadata_response). 
    If redaction_mode is False (analyze-only), sanitized_pdf_bytes is None.
    """
    start_time = time.perf_counter()
    req_id = getattr(request.state, "request_id", "unknown")

    # 1. Pipeline: Hashing & Caching
    file_hash = compute_sha256(file_bytes)
    
    # We only cache fully redacted files, not analyze-only results.
    if redaction_mode:
        cached_result = await request.app.state.cache.get(file_hash)
        if cached_result:
            metrics.CACHE_HITS.inc()
            metrics.REQUEST_COUNT.labels(status="200").inc()
            
            processing_time_ms = (time.perf_counter() - start_time) * 1000
            resp_metadata = SanitizeResponse(
                request_id=req_id, filename=filename, file_hash=file_hash,
                cache_hit=True, pages_processed=0, ocr_used=False,
                pii_entities_found=0, entities=[], processing_time_ms=processing_time_ms,
                sanitized_pdf_size_bytes=len(cached_result)
            )
            return cached_result, resp_metadata

    metrics.CACHE_MISSES.inc()
    metrics.FILE_SIZE_BYTES.observe(len(file_bytes))

    # CPU-bound tasks must run in thread executor to not block the FastAPI async event loop
    loop = asyncio.get_running_loop()

    # 2. Pipeline: Parsing & OCR Extraction
    doc, blocks, ocr_used = await loop.run_in_executor(None, extract, file_bytes)
    if ocr_used:
        metrics.OCR_USAGE.inc()

    # 3. Pipeline: 3-Layer PII Analysis
    entities = await loop.run_in_executor(None, analyze, request.app.state.analyzer, doc, blocks, ocr_used, min_confidence)
    
    # Feature: Selective Redaction
    if redact_types:
        user_requested_types = {t.strip().upper() for t in redact_types.split(",")}
        entities = [e for e in entities if e.entity_type.upper() in user_requested_types]

    metrics.PII_ENTITIES_FOUND.observe(len(entities))

    sanitized_bytes = None

    # 4. Pipeline: Redaction (only if requested)
    if redaction_mode:
        targets = await loop.run_in_executor(None, build_redaction_targets, doc, entities, blocks, ocr_used)
        sanitized_bytes = await loop.run_in_executor(None, apply_redactions, doc, targets)
        
        # 5. Store in cache
        await request.app.state.cache.set(file_hash, sanitized_bytes, settings.CACHE_TTL_SECONDS)

    proc_time_ms = (time.perf_counter() - start_time) * 1000
    metrics.REQUEST_LATENCY.observe(proc_time_ms / 1000.0)
    metrics.REQUEST_COUNT.labels(status="200").inc()
    
    # Normally we'd close the doc in the parser loop, but since we had to pass `doc` 
    # out for redaction, if we didn't redact, we must explicitly close it here.
    if not redaction_mode and doc:
        doc.close()

    metadata = SanitizeResponse(
        request_id=req_id,
        filename=filename,
        file_hash=file_hash,
        cache_hit=False,
        pages_processed=len(blocks),
        ocr_used=ocr_used,
        pii_entities_found=len(entities),
        entities=entities,
        processing_time_ms=proc_time_ms,
        sanitized_pdf_size_bytes=len(sanitized_bytes) if sanitized_bytes else 0
    )

    return sanitized_bytes, metadata


@app.post(f"{settings.API_PREFIX}/sanitize", response_class=Response)
async def sanitize_resume(
    request: Request,
    file: UploadFile = File(...),
    return_metadata: bool = Query(False, description="Include PII entity metadata in response headers"),
    min_confidence: float = Query(0.55, ge=0.0, le=1.0, description="Minimum Presidio confidence score"),
    redact_types: str = Query(None, description="Comma-separated list of entities to redact")
) -> Response:
    """Primary endpoint. Ingests a PDF and spits back a permanent-blacked-out version."""
    if file.content_type not in settings.ALLOWED_CONTENT_TYPES:
        # Some clients send application/octet-stream for PDF uploads
        if file.content_type != "application/octet-stream" or not (file.filename or "").lower().endswith(".pdf"):
            metrics.REQUEST_COUNT.labels(status="415").inc()
            raise InvalidFileTypeError()

    pdf_bytes = await file.read()
    
    sanitized_bytes, metadata = await process_pdf(
        request=request, 
        file_bytes=pdf_bytes, 
        filename=file.filename or "upload.pdf", 
        min_confidence=min_confidence, 
        redaction_mode=True, 
        redact_types=redact_types
    )
    
    headers = {
        "Content-Disposition": f'attachment; filename="sanitized_{file.filename}"',
        "X-Request-ID": metadata.request_id,
        "X-PII-Count": str(metadata.pii_entities_found),
        "X-OCR-Used": "true" if metadata.ocr_used else "false",
        "X-Cache": "HIT" if metadata.cache_hit else "MISS",
        "X-Processing-Time-Ms": str(round(metadata.processing_time_ms, 2))
    }
    
    if return_metadata:
        import json
        manifest = [{"type": e.entity_type, "layer": e.detection_layer, "score": e.score, "page": e.page} for e in metadata.entities]
        headers["X-Redaction-Manifest"] = json.dumps(manifest)

    return Response(
        content=sanitized_bytes,  # type: ignore[arg-type]
        media_type="application/pdf",
        headers=headers,
    )


@app.post(f"{settings.API_PREFIX}/analyze-only", response_model=SanitizeResponse)
async def analyze_only(
    request: Request,
    file: UploadFile = File(...),
    min_confidence: float = Query(0.55, ge=0.0, le=1.0)
):
    """Dry-run endpoint. Audits the PDF for PII but does not perform the expensive redaction."""
    if file.content_type not in settings.ALLOWED_CONTENT_TYPES:
        raise InvalidFileTypeError()

    pdf_bytes = await file.read()
    _, metadata = await process_pdf(
        request=request, 
        file_bytes=pdf_bytes, 
        filename=file.filename or "upload.pdf", 
        min_confidence=min_confidence, 
        redaction_mode=False
    )
    
    return metadata


@app.post(f"{settings.API_PREFIX}/batch")
async def batch_sanitize(
    request: Request,
    files: List[UploadFile] = File(..., max_items=10),
    min_confidence: float = Query(0.55, ge=0.0, le=1.0)
):
    """Async endpoint that processes up to 10 files truly concurrently."""
    
    async def process_single(f: UploadFile):
        if f.content_type not in settings.ALLOWED_CONTENT_TYPES:
            return {"filename": f.filename, "error": "Invalid file type. Only PDF is supported."}
            
        pdf_bytes = await f.read()
        try:
            sanitized_bytes, metadata = await process_pdf(
                request=request, 
                file_bytes=pdf_bytes, 
                filename=f.filename or "upload.pdf", 
                min_confidence=min_confidence, 
                redaction_mode=True
            )
            
            # Encode so we can return standard JSON
            encoded = base64.b64encode(sanitized_bytes).decode('utf-8') if sanitized_bytes else None # type: ignore
            
            return {
                "metadata": metadata.model_dump(),
                "base64_pdf": encoded
            }
        except Exception as e:
            return {"filename": f.filename, "error": str(e)}

    # Gather handles spinning them off securely into async land
    results = await asyncio.gather(*(process_single(f) for f in files))
    return {"results": results}
