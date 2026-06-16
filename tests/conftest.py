import pytest
import pytest_asyncio
import fitz
from httpx import AsyncClient, ASGITransport
import io

from resume_sanitizer.main import app
from resume_sanitizer.analyzer import build_analyzer_engine

# 🎓 Teacher Note: `scope="session"` means this fixture runs ONCE for the entire
# test suite, not once per test. Loading spaCy takes ~5 seconds, so we only do it once.
@pytest.fixture(scope="session")
def analyzer_engine():
    return build_analyzer_engine()

@pytest.fixture
def sample_digital_pdf_bytes():
    """
    Builds a real PDF in memory with highly identifiable test data.
    
    🎓 Teacher Note: We use fitz.open() to create a PDF from scratch.
    This is faster than loading a file from disk and gives us full control
    over what PII is in the document.
    """
    doc = fitz.open()
    page = doc.new_page()
    
    # Large font at top half -> Name heuristic should catch this
    page.insert_text((50, 50), "UTKARSH KUMAR", fontsize=24)
    # Regex hits (these should be caught by Layer 1)
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
    """
    Simulates a scanned PDF (an image embedded in a PDF without a text layer).
    """
    doc = fitz.open()
    page = doc.new_page()
    page.draw_rect(page.rect, color=(0.5, 0.5, 0.5), fill=(0.8, 0.8, 0.8))
    
    pdf_bytes = doc.write()
    doc.close()
    return pdf_bytes

@pytest_asyncio.fixture
async def async_client():
    """
    🎓 Teacher Note: httpx's AsyncClient does NOT automatically trigger
    FastAPI's lifespan events (startup/shutdown). But our app's lifespan
    handler is where we load the analyzer engine and initialize the cache
    (app.state.analyzer and app.state.cache).

    Solution: We manually enter the lifespan context manager before
    creating the test client. This runs the startup code (loading spaCy,
    connecting cache) and ensures the shutdown code runs after tests finish.
    """
    # Manually trigger the lifespan to populate app.state
    async with app.router.lifespan_context(app):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            yield ac

