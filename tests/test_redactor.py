import fitz
from resume_sanitizer.parser import extract_text_digital
from resume_sanitizer.analyzer import analyze
from resume_sanitizer.redactor import build_redaction_targets, apply_redactions

def test_redaction_removes_text_from_pdf(sample_digital_pdf_bytes, analyzer_engine):
    # 1. Parse
    doc, blocks = extract_text_digital(sample_digital_pdf_bytes)
    
    # 2. Analyze
    entities = analyze(analyzer_engine, doc, blocks, False, 0.55)
    assert len(entities) > 2 # We seeded a Name, Email, Phone, LinkedIn, Aadhaar
    
    # 3. Redact
    targets = build_redaction_targets(doc, entities, blocks, False)
    sanitized_bytes = apply_redactions(doc, targets)
    
    # 4. Verify text is actually gone structurally!
    clean_doc = fitz.open(stream=sanitized_bytes, filetype="pdf")
    clean_text = clean_doc[0].get_text("text")

    # The actual strings should no longer live in the PDF
    assert "testuser@example.com" not in clean_text
    assert "+91 9999999999" not in clean_text
    assert "UTKARSH" not in clean_text

def test_redaction_metadata_scrubbed(sample_digital_pdf_bytes, analyzer_engine):
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
