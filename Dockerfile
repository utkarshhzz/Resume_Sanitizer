FROM python:3.11-slim-bookworm

# System deps for PyMuPDF, Tesseract OCR, and pdf2image
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    poppler-utils \
    libmupdf-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first (layer cache — only rebuilds if requirements.txt changes)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Bake the spaCy model into the image (avoids runtime download)
RUN python -m spacy download en_core_web_lg

# Copy application code
COPY resume_sanitizer/ ./resume_sanitizer/
COPY prometheus.yml .

# Run as non-root for security
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Set offline mode so no runtime network calls are attempted
ENV OFFLINE_MODE=true
ENV TRANSFORMERS_OFFLINE=1
ENV HF_DATASETS_OFFLINE=1
ENV HF_HUB_OFFLINE=1

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Production server — single worker (spaCy model is ~600MB per worker)
CMD ["gunicorn", "resume_sanitizer.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "1", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--preload", \
     "--access-logfile", "-"]
