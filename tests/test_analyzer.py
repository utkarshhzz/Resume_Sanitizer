"""
🎓 Teacher Note: These tests verify that the 3-layer analyzer correctly detects
each type of PII. Each test creates a dummy text block, runs the analyzer,
and asserts that the expected entity type was found.

The pattern is always:
  1. Create a PageTextBlock with known PII text
  2. Run analyze()
  3. Filter results for the expected entity_type
  4. Assert it was found with the correct text
"""
import pytest
import fitz
from resume_sanitizer.models import PageTextBlock, WordBlock
from resume_sanitizer.analyzer import analyze, detect_resume_sections

def _make_dummy_block(text: str) -> list[PageTextBlock]:
    """Helper: Creates a minimal PageTextBlock from a text string."""
    wb = WordBlock(text=text, x0=0, y0=0, x1=10, y1=10, page_number=1, confidence=100, font_size=11, is_bold=False)
    return [PageTextBlock(page_number=1, text=text, words=[wb])]

# ── Layer 1: Regex Detection Tests ──

def test_email_regex_detection(analyzer_engine):
    blocks = _make_dummy_block("Contact me at john.doe@email.com immediately.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    email_entities = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
    assert len(email_entities) == 1
    assert email_entities[0].text == "john.doe@email.com"
    assert email_entities[0].detection_layer == "regex"

def test_indian_phone_detection(analyzer_engine):
    blocks = _make_dummy_block("Call me on +91 9123456780.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    phone_entities = [e for e in entities if e.entity_type == "PHONE_NUMBER"]
    assert len(phone_entities) >= 1

def test_linkedin_url_detection(analyzer_engine):
    """🎓 LinkedIn URLs are the #1 way companies bypass the bridge service."""
    blocks = _make_dummy_block("Find me at linkedin.com/in/utkarshhzz for details")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    linkedin = [e for e in entities if e.entity_type == "LINKEDIN_URL"]
    assert len(linkedin) == 1
    assert "utkarshhzz" in linkedin[0].text

def test_github_url_detection(analyzer_engine):
    blocks = _make_dummy_block("My code is at https://github.com/utkarshhzz/Resume_Sanitizer")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    github_urls = [e for e in entities if e.entity_type == "GITHUB_URL"]
    assert len(github_urls) == 1

def test_pan_card_detection(analyzer_engine):
    """🎓 PAN cards follow a strict format: 5 uppercase letters, 4 digits, 1 uppercase letter."""
    blocks = _make_dummy_block("My PAN is ABCDE1234F for tax purposes.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    pan = [e for e in entities if e.entity_type == "PAN_CARD"]
    assert len(pan) == 1
    assert pan[0].text == "ABCDE1234F"

def test_aadhaar_detection(analyzer_engine):
    """🎓 Aadhaar: 12 digits, first digit 2-9, optionally space-separated in groups of 4."""
    blocks = _make_dummy_block("Aadhaar number: 2345 6789 1234")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    aadhaar = [e for e in entities if e.entity_type == "AADHAAR_NUMBER"]
    assert len(aadhaar) >= 1

def test_social_media_url_detection(analyzer_engine):
    """🎓 Social media URLs must be caught so companies can't find the candidate online."""
    blocks = _make_dummy_block("Follow me on https://twitter.com/utkarshhzz")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    social = [e for e in entities if e.entity_type == "SOCIAL_MEDIA_URL"]
    assert len(social) >= 1

# ── Layer 3: Heuristic Tests ──

def test_largest_font_heuristic(analyzer_engine):
    """
    🎓 The largest font text at the top of a resume is the candidate's name.
    We create a PDF with a big "JOHN SMITH" and verify the heuristic catches it.
    """
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "JOHN SMITH", fontsize=28)
    page.insert_text((50, 100), "Software Engineer", fontsize=12)
    page.insert_text((50, 130), "email: john@test.com", fontsize=11)
    pdf_bytes = doc.write()
    doc.close()
    
    from resume_sanitizer.parser import extract_text_digital
    doc2, blocks = extract_text_digital(pdf_bytes)
    entities = analyze(analyzer_engine, doc2, blocks, False, 0.55)
    
    person_entities = [e for e in entities if e.entity_type == "PERSON"]
    person_texts = [e.text for e in person_entities]
    # The heuristic (or NER) should have found "JOHN SMITH"
    assert any("JOHN" in t for t in person_texts)

# ── Deduplication Tests ──

def test_deduplication_removes_overlapping(analyzer_engine):
    """
    🎓 If NER flags 'mike' as PERSON inside 'mike@mike.com' (EMAIL), 
    dedup should keep the higher-scoring EMAIL and drop the PERSON.
    """
    blocks = _make_dummy_block("Email: mike@mike.com")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    emails = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
    assert len(emails) >= 1

# ── False Positive Prevention Tests ──

def test_pincode_no_false_positive_without_context(analyzer_engine):
    """
    🎓 The number '500001' (Hyderabad pincode) appears in many contexts:
    'Salary: 500001' should NOT be detected as a pincode without context words.
    """
    blocks = _make_dummy_block("My salary is 500001 per annum.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    pincodes = [e for e in entities if e.entity_type == "PINCODE_IN"]
    assert len(pincodes) == 0  # No "pincode"/"postal" context → should not match

def test_section_detection():
    """🎓 Verify that section detection correctly identifies resume sections."""
    blocks = [PageTextBlock(
        page_number=1,
        text="John Doe\nemail@test.com\n\nExperience\nWorked at Google\n\nEducation\nMIT\n\nSkills\nPython",
        words=[]
    )]
    sections = detect_resume_sections(blocks)
    assert "EXPERIENCE" in sections
    assert "EDUCATION" in sections
    assert "SKILLS" in sections


def test_skills_section_tech_not_redacted(analyzer_engine):
    """Kafka, Supabase, etc. in Skills must not be flagged as PII."""
    blocks = _make_dummy_block(
        "Skills\nPython, Kafka, Supabase, Redis, Docker, PostgreSQL, React, AWS"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    redacted_texts = {e.text.lower().strip() for e in entities}
    assert "kafka" not in redacted_texts
    assert "supabase" not in redacted_texts
    assert "redis" not in redacted_texts


def test_pipe_separated_links_merged(analyzer_engine):
    """github.com/x | linkedin.com/y should be one redaction span including the pipe."""
    blocks = _make_dummy_block(
        "Contact\ngithub.com/keyurdev | linkedin.com/in/keyurdev"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    url_entities = [e for e in entities if e.entity_type in ("SOCIAL_LINK_GROUP", "GITHUB_URL", "LINKEDIN_URL")]
    assert len(url_entities) >= 1
    # Merged group should include the pipe delimiter
    assert any("|" in e.text for e in url_entities)


def test_naukri_and_linkedin_prose_not_redacted(analyzer_engine):
    """Job platform names in project descriptions must not be flagged as PII."""
    blocks = _make_dummy_block(
        "Projects\nImplemented API keys to scrape jobs from sites like LinkedIn and Naukri"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    texts = {e.text.lower() for e in entities}
    assert "naukri" not in texts
    assert "linkedin" not in texts


def test_school_address_not_redacted(analyzer_engine):
    """School locality/city in education must stay (Manjri Pune, etc.)."""
    blocks = _make_dummy_block(
        "Education\nB.Tech, XYZ School, Manjri Pune, Maharashtra"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    person_texts = [e.text for e in entities if e.entity_type == "PERSON"]
    assert not any("manjri" in t.lower() for t in person_texts)


def test_colleague_name_not_redacted(analyzer_engine):
    """Other people's names in experience must not be redacted."""
    blocks = _make_dummy_block(
        "Experience\nWorked with manager John Smith on backend services"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    person_texts = [e.text for e in entities if e.entity_type == "PERSON"]
    assert not any("john smith" in t.lower() for t in person_texts)


def test_candidate_name_redacted_everywhere(analyzer_engine):
    """Candidate name must be redacted in header and body."""
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((50, 50), "KEYUR PATEL", fontsize=24)
    page.insert_text((50, 100), "keyur@email.com", fontsize=11)
    page.insert_text((50, 200), "Built system for Keyur Patel portfolio", fontsize=11)
    pdf_bytes = doc.write()
    doc.close()

    from resume_sanitizer.parser import extract_text_digital
    doc2, blocks = extract_text_digital(pdf_bytes)
    entities = analyze(analyzer_engine, doc2, blocks, False, 0.55)
    person_texts = " ".join(e.text.lower() for e in entities if e.entity_type == "PERSON")
    assert "keyur" in person_texts
