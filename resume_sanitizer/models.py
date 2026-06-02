from __future__ import annotations

from pydantic import BaseModel, ConfigDict

# --- REQUEST / RESPONSE SCHEMAS ---

class SanitizeRequest(BaseModel):
    """Internal model for the request data."""
    model_config = ConfigDict(frozen=True)

    file_hash: str
    filename: str
    content_type: str
    file_size_bytes: int


class PIIEntity(BaseModel):
    """Represents a single piece of sensitive data detected in the text."""
    model_config = ConfigDict(frozen=True)

    entity_type: str          # e.g., "EMAIL_ADDRESS", "PERSON"
    text: str                 # Original matched text
    score: float              # Confidence score from 0.0 to 1.0
    page: int                 # 1-indexed page number
    detection_layer: str      # "regex" | "presidio_ner" | "heuristic" | "ocr_context"
    start: int                # Character start offset in page text
    end: int                  # Character end offset in page text


class SanitizeResponse(BaseModel):
    """The final response sent back to the user upon a 'dry run' or batch metadata request."""
    model_config = ConfigDict(frozen=True)

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


# --- INTERNAL DTOs (Data Transfer Objects) ---

class WordBlock(BaseModel):
    """Represents a single mapped word from PyMuPDF or Tesseract OCR."""
    model_config = ConfigDict(frozen=True)

    text: str
    x0: float
    y0: float
    x1: float
    y1: float
    page_number: int          # 1-indexed
    confidence: int           # Tesseract conf (0-100), -1 for digital path
    font_size: float          # Points; -1 for OCR path
    is_bold: bool


class PageTextBlock(BaseModel):
    """All combined text and word-level coordinate maps for a single PDF page."""
    model_config = ConfigDict(frozen=True)

    page_number: int          # 1-indexed
    text: str                 # Full page text concatenated
    words: list[WordBlock]    # Word-level details


class RedactionTarget(BaseModel):
    """Instructs the Redactor exactly where and what to redact."""
    model_config = ConfigDict(frozen=True)

    page_number: int
    entity_type: str
    original_text: str
    rects: list[tuple[float, float, float, float]]  # List of coordinates (x0, y0, x1, y1)
    source: str               # "digital" | "ocr"
