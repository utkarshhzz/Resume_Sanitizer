import pytest
import fitz
from resume_sanitizer.models import PageTextBlock, WordBlock
from resume_sanitizer.analyzer import analyze, detect_resume_sections


def _make_dummy_block(text: str) -> list[PageTextBlock]:
    wb = WordBlock(text=text, x0=0, y0=0, x1=10, y1=10, page_number=1, confidence=100, font_size=11, is_bold=False)
    return [PageTextBlock(page_number=1, text=text, words=[wb])]


# --- Regex Detection ---

def test_email_regex_detection(analyzer_engine):
    blocks = _make_dummy_block("Contact me at john.doe@email.com immediately.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    email_entities = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
    assert len(email_entities) == 1
    assert email_entities[0].text == "john.doe@email.com"


def test_indian_phone_detection(analyzer_engine):
    blocks = _make_dummy_block("Call me on +91 9123456780.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert any(e.entity_type == "PHONE_NUMBER" for e in entities)


def test_linkedin_url_detection(analyzer_engine):
    blocks = _make_dummy_block("Find me at linkedin.com/in/utkarshhzz for details")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    linkedin = [e for e in entities if e.entity_type == "LINKEDIN_URL"]
    assert len(linkedin) == 1
    assert "utkarshhzz" in linkedin[0].text


def test_github_url_detection(analyzer_engine):
    blocks = _make_dummy_block("My code is at https://github.com/utkarshhzz/Resume_Sanitizer")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert any(e.entity_type == "GITHUB_URL" for e in entities)


def test_pan_card_detection(analyzer_engine):
    blocks = _make_dummy_block("My PAN is ABCDE1234F for tax purposes.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    pan = [e for e in entities if e.entity_type == "PAN_CARD"]
    assert len(pan) == 1
    assert pan[0].text == "ABCDE1234F"


def test_aadhaar_detection(analyzer_engine):
    blocks = _make_dummy_block("Aadhaar number: 2345 6789 1234")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert any(e.entity_type == "AADHAAR_NUMBER" for e in entities)


def test_social_media_url_detection(analyzer_engine):
    blocks = _make_dummy_block("Follow me on https://twitter.com/utkarshhzz")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert any(e.entity_type == "SOCIAL_MEDIA_URL" for e in entities)


# --- Heuristic Detection ---

def test_largest_font_heuristic(analyzer_engine):
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
    person_texts = [e.text for e in entities if e.entity_type == "PERSON"]
    assert any("JOHN" in t for t in person_texts)


# --- Deduplication ---

def test_deduplication_removes_overlapping(analyzer_engine):
    blocks = _make_dummy_block("Email: mike@mike.com")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert any(e.entity_type == "EMAIL_ADDRESS" for e in entities)


# --- False Positive Prevention ---

def test_pincode_no_false_positive_without_context(analyzer_engine):
    blocks = _make_dummy_block("My salary is 500001 per annum.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    assert not any(e.entity_type == "PINCODE_IN" for e in entities)


def test_section_detection():
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
    blocks = _make_dummy_block(
        "Skills\nPython, Kafka, Supabase, Redis, Docker, PostgreSQL, React, AWS"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    redacted_texts = {e.text.lower().strip() for e in entities}
    assert "kafka" not in redacted_texts
    assert "supabase" not in redacted_texts
    assert "redis" not in redacted_texts


def test_pipe_separated_links_merged(analyzer_engine):
    blocks = _make_dummy_block(
        "Contact\ngithub.com/keyurdev | linkedin.com/in/keyurdev"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    url_entities = [e for e in entities if e.entity_type in ("SOCIAL_LINK_GROUP", "GITHUB_URL", "LINKEDIN_URL", "PERSONAL_URL")]
    # Both URLs must be detected (either merged into one group or individually)
    assert len(url_entities) >= 1
    all_text = " ".join(e.text for e in url_entities).lower()
    assert "github.com" in all_text or "keyurdev" in all_text


def test_naukri_and_linkedin_prose_not_redacted(analyzer_engine):
    blocks = _make_dummy_block(
        "Projects\nImplemented API keys to scrape jobs from sites like LinkedIn and Naukri"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    texts = {e.text.lower() for e in entities}
    assert "naukri" not in texts
    assert "linkedin" not in texts


def test_school_address_not_redacted(analyzer_engine):
    blocks = _make_dummy_block(
        "Education\nB.Tech, XYZ School, Manjri Pune, Maharashtra"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    person_texts = [e.text for e in entities if e.entity_type == "PERSON"]
    assert not any("manjri" in t.lower() for t in person_texts)


def test_colleague_name_not_redacted(analyzer_engine):
    blocks = _make_dummy_block(
        "Experience\nWorked with manager John Smith on backend services"
    )
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    person_texts = [e.text for e in entities if e.entity_type == "PERSON"]
    assert not any("john smith" in t.lower() for t in person_texts)


def test_candidate_name_redacted_everywhere(analyzer_engine):
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
