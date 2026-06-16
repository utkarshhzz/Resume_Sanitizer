from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Central Configuration for the Resume Sanitizer.
    All settings can be overridden via a .env file or environment variables.
    """
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    # Environment
    APP_ENV: str = "development"            # "development" | "staging" | "production"
    APP_VERSION: str = "1.0.0"
    LOG_LEVEL: str = "INFO"

    # API Configuration
    API_PREFIX: str = "/api/v1"
    MAX_UPLOAD_SIZE_MB: int = 20           # Reject files larger than this
    ALLOWED_CONTENT_TYPES: list[str] = ["application/pdf"]
    REQUEST_TIMEOUT_SECONDS: int = 30
    CORS_ORIGINS: list[str] = ["*"]

    # OCR Rules (When text can't be easily extracted)
    OCR_CHAR_THRESHOLD: int = 50           # Min chars before triggering OCR fallback
    OCR_DPI: int = 300                     # DPI for pdf2image conversion
    OCR_LANGUAGE: str = "eng"              # Tesseract language
    OCR_CONFIDENCE_THRESHOLD: int = 40     # Min Tesseract word confidence to include

    # Presidio / NLP (Layer 2 specific)
    SPACY_MODEL: str = "en_core_web_lg"
    USE_ONNX_NER: bool = False             # Toggle ONNX model vs spaCy (for future speedup)
    ONNX_MODEL_PATH: str = "models/ner_model.onnx"

    # Caching (To avoid doing work twice)
    CACHE_BACKEND: str = "memory"          # "memory" | "redis"
    REDIS_URL: str = "redis://localhost:6379/0"
    CACHE_TTL_SECONDS: int = 3600          # 1 hour

    # Rate Limiting
    RATE_LIMIT_REQUESTS: int = 100
    RATE_LIMIT_WINDOW_SECONDS: int = 60

    # Redaction Styling
    REDACTION_FILL_COLOR: tuple[float, float, float] = (1.0, 1.0, 1.0)  # RGB white — invisible redaction
    REDACTION_PADDING_PX: int = 2          # Extra pixels around each box to ensure no text leaks

settings = Settings()
