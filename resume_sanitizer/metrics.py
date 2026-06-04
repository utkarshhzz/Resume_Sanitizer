from __future__ import annotations

from prometheus_client import Counter, Histogram

# Total calls made to the service, tagged by whether it succeeded or failed HTTP code
REQUEST_COUNT = Counter(
    "sanitizer_requests_total", 
    "Total sanitize requests", 
    ["status"]
)

# Tracks how fast our API responds (we group these into buckets from 0.1 secs to 10 seconds)
REQUEST_LATENCY = Histogram(
    "sanitizer_request_duration_seconds", 
    "Request duration", 
    buckets=[0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0]
)

# Tracks how incredibly private a resume was (e.g. some resumes have 0 things, others have 50 PII entries!)
PII_ENTITIES_FOUND = Histogram(
    "sanitizer_pii_entities_per_document", 
    "PII count per doc", 
    buckets=[0, 1, 5, 10, 20, 50, 100]
)

# If this starts spiking, it means people are uploading a lot of terrible quality scanned photos
OCR_USAGE = Counter(
    "sanitizer_ocr_fallback_total", 
    "Times OCR fallback triggered"
)

# Tracks how good our cache system is performing
CACHE_HITS = Counter("sanitizer_cache_hits_total", "Cache hit count")
CACHE_MISSES = Counter("sanitizer_cache_misses_total", "Cache miss count")

# Tracks how giant the PDFs are (mostly useful for tuning AWS server memory)
FILE_SIZE_BYTES = Histogram(
    "sanitizer_file_size_bytes", 
    "Input PDF size", 
    buckets=[1e4, 1e5, 5e5, 1e6, 5e6, 2e7] # 10KB to 20MB
)
