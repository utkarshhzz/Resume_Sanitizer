FROM python:3.11-slim-bookworm

# 1. Install system dependencies
# PyMuPDF and Tesseract require C-level system libraries to process images and PDFs.
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    tesseract-ocr-eng \
    poppler-utils \
    libmupdf-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 2. Layer Cache Optimization
# We copy ONLY the requirements file first. If we don't change our packages,
# Docker caches this step and skips it on future builds, saving minutes!
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 3. Bake in the ML Model
# We download the NLP model inside the Docker image so the container 
# doesn't have to download it from the internet every time it spins up (which causes huge cold-start delays).
RUN python -m spacy download en_core_web_lg

# 4. Copy the actual application code
COPY . .

# 5. Security: Run as a non-root user
# If a hacker somehow breaks out of the Python app, they won't have root permissions on the container.
RUN adduser --disabled-password --gecos "" appuser
USER appuser

EXPOSE 8000

# 6. Production Server Command
# Using Gunicorn with Uvicorn workers gives us the best of both worlds:
# Gunicorn handles process management (restarting dead workers), and Uvicorn handles the Async event loop.
CMD ["gunicorn", "resume_sanitizer.main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "60", \
     "--preload", \
     "--access-logfile", "-"]
