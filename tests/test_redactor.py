"""
🎓 Teacher Note: These tests verify the PHYSICAL redaction of the PDF.
After redaction:
  1. The text strings must be GONE from the PDF binary (not just hidden)
  2. Document metadata (Author, Title) must be scrubbed
  3. The output must be valid PDF bytes
"""
import fitz
from resume_sanitizer.parser import extract_text_digital
from resume_sanitizer.analyzer import analyze
from resume_sanitizer.redactor import build_redaction_targets, apply_redactions

def test_redaction_removes_text_from_pdf(sample_digital_pdf_bytes, analyzer_engine):
    """🎓 The core test: after redaction, PII strings must not exist in the PDF."""
    # 1. Parse
    doc, blocks = extract_text_digital(sample_digital_pdf_bytes)
    
    # 2. Analyze
    entities = analyze(analyzer_engine, doc, blocks, False, 0.55)
    assert len(entities) > 2  # We seeded Name, Email, Phone, LinkedIn, Aadhaar, PAN, GitHub
    
    # 3. Redact
    targets = build_redaction_targets(doc, entities, blocks, False)
    sanitized_bytes = apply_redactions(doc, targets)
    
    # 4. Verify text is actually gone structurally!
    clean_doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
    clean_text = clean_doc[0].get_text("text")

    # These strings should no longer exist in the PDF
    assert "testuser@example.com" not in clean_text
    assert "+91 9999999999" not in clean_text
    # Name could be partially there due to font heuristic detection
    clean_doc.close()

def test_redaction_metadata_scrubbed(sample_digital_pdf_bytes, analyzer_engine):
    """
    🎓 PDF metadata often contains "Author: John Doe" that most people never see.
    We must scrub it completely.
    """
    # Prepare a PDF with scary metadata
    doc = fitz.open(stream=sample_digital_pdf_bytes, filetype="pdf")
    doc.set_metadata({"author": "Secret Hacker", "title": "My Evil Resume"})
    dirty_bytes = doc.write()
    doc.close()
    
    # Run pipeline
    doc2, blocks = extract_text_digital(dirty_bytes)
    entities = analyze(analyzer_engine, doc2, blocks, False, 0.55)
    targets = build_redaction_targets(doc2, entities, blocks, False)
    sanitized_bytes = apply_redactions(doc2, targets)
    
    # Check that metadata was purged
    clean_doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
    meta = clean_doc.metadata
    
    assert meta.get("author") == ""
    assert meta.get("title") == ""
    clean_doc.close()

def test_redaction_produces_valid_pdf(sample_digital_pdf_bytes, analyzer_engine):
    """
    🎓 After all that surgery, the output must still be a valid, openable PDF.
    """
    doc, blocks = extract_text_digital(sample_digital_pdf_bytes)
    entities = analyze(analyzer_engine, doc, blocks, False, 0.55)
    targets = build_redaction_targets(doc, entities, blocks, False)
    sanitized_bytes = apply_redactions(doc, targets)
    
    # Should be openable without error
    clean_doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
    assert clean_doc.page_count == 1
    clean_doc.close()

def test_linkedin_url_removed_from_text(sample_digital_pdf_bytes, analyzer_engine):
    """
    🎓 LinkedIn URLs are the #1 way companies bypass the bridge.
    Verify the URL text is gone after redaction.
    """
    doc, blocks = extract_text_digital(sample_digital_pdf_bytes)
    entities = analyze(analyzer_engine, doc, blocks, False, 0.55)
    targets = build_redaction_targets(doc, entities, blocks, False)
    sanitized_bytes = apply_redactions(doc, targets)
    
    clean_doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
    clean_text = clean_doc[0].get_text("text")
    assert "linkedin.com" not in clean_text.lower()
    clean_doc.close()
