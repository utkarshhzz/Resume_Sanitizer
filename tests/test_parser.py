import pytest
from resume_sanitizer.parser import extract_text_digital, needs_ocr, extract
from resume_sanitizer.exceptions import PDFCorruptedError

def test_digital_extraction_returns_text(sample_digital_pdf_bytes):
    doc, blocks = extract_text_digital(sample_digital_pdf_bytes)
    assert doc is not None
    assert len(blocks) == 1
    
    page_text = blocks[0].text
    assert "UTKARSH KUMAR" in page_text
    assert "testuser@example.com" in page_text
    
    total_chars = sum(len(b.text.strip()) for b in blocks)
    assert total_chars > 50

def test_needs_ocr_identifies_images(sample_scanned_pdf_bytes):
    doc, blocks = extract_text_digital(sample_scanned_pdf_bytes)
    assert needs_ocr(blocks) is True

def test_corrupt_pdf_raises():
    corrupt_bytes = b"NOT A PDF AT ALL %PDF THIS IS GARBAGE"
    with pytest.raises(PDFCorruptedError):
        extract(corrupt_bytes)
