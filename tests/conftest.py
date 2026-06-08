import pytest
import fitz
from httpx import AsyncClient, ASGITransport
import io

from resume_sanitizer.main import app
from resume_sanitizer.analyzer import build_analyzer_engine

@pytest.fixture(scope="session")
def analyzer_engine():
    # Load once for all tests to speed them up
    return build_analyzer_engine()

@pytest.fixture
def sample_digital_pdf_bytes():
    """Builds a real PDF in memory with highly identifiable test data."""
    doc = fitz.open()
    page = doc.new_page()
    
    # Large font at top half -> Name heuristic
    page.insert_text((50, 50), "UTKARSH KUMAR", fontsize=24)
    # Regex hits
    page.insert_text((50, 100), "Email: testuser@example.com", fontsize=11)
    page.insert_text((50, 120), "Phone: +91 9999999999", fontsize=11)
    page.insert_text((50, 140), "LinkedIn: linkedin.com/in/utkarshhzz", fontsize=11)
    page.insert_text((50, 160), "Aadhaar: 2345 6789 1234", fontsize=11)
    
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes

@pytest.fixture
def sample_scanned_pdf_bytes():
    """
    Simulates a scanned PDF (an image embedded in a PDF without a text layer).
    """
    doc = fitz.open()
    page = doc.new_page()
    # Draw a blank rectangle (acts like an image container with no readable text)
    page.draw_rect(page.rect, color=(0.5, 0.5, 0.5), fill=(0.8, 0.8, 0.8))
    
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes

@pytest.fixture
async def async_client():
    # Trigger lifespan to ensure analyzer/cache is loaded
    async with ASGITransport(app=app) as transport:
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
