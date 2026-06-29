import pytest
import pytest_asyncio
import fitz
from httpx import AsyncClient, ASGITransport

from resume_sanitizer.main import app
from resume_sanitizer.analyzer import build_analyzer_engine


@pytest.fixture(scope="session")
def analyzer_engine():
    return build_analyzer_engine()


@pytest.fixture
def sample_digital_pdf_bytes():
    """Build a test PDF with known PII data."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "UTKARSH KUMAR", fontsize=24)
    page.insert_text((50, 100), "Email: testuser@example.com", fontsize=11)
    page.insert_text((50, 120), "Phone: +91 9999999999", fontsize=11)
    page.insert_text((50, 140), "LinkedIn: linkedin.com/in/utkarshhzz", fontsize=11)
    page.insert_text((50, 160), "Aadhaar: 2345 6789 1234", fontsize=11)
    page.insert_text((50, 180), "PAN: ABCDE1234F", fontsize=11)
    page.insert_text((50, 200), "GitHub: github.com/utkarshhzz", fontsize=11)
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes


@pytest.fixture
def sample_scanned_pdf_bytes():
    """Simulate a scanned PDF (no text layer)."""
    doc = fitz.open()
    page = doc.new_page()
    page.draw_rect(page.rect, color=(0.5, 0.5, 0.5), fill=(0.8, 0.8, 0.8))
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes


@pytest_asyncio.fixture
async def async_client():
    """Manually trigger lifespan to populate app.state before testing."""
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac
