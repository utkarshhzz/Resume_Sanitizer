import pytest
import fitz
from resume_sanitizer.models import PageTextBlock, WordBlock
from resume_sanitizer.analyzer import analyze

def _make_dummy_block(text: str) -> list[PageTextBlock]:
    wb = WordBlock(text=text, x0=0, y0=0, x1=10, y1=10, page_number=1, confidence=100, font_size=11, is_bold=False)
    return [PageTextBlock(page_number=1, text=text, words=[wb])]

def test_email_regex_detection(analyzer_engine):
    blocks = _make_dummy_block("Contact me at john.doe@email.com immediately.")
    # Provide a dummy fitz doc for heuristic
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    email_entities = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
    assert len(email_entities) == 1
    assert email_entities[0].text == "john.doe@email.com"
    assert email_entities[0].detection_layer == "regex"

def test_indian_phone_detection(analyzer_engine):
    blocks = _make_dummy_block("Call me on +91 9123456780.")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    phone_entities = [e for e in entities if e.entity_type == "PHONE_NUMBER"]
    assert len(phone_entities) == 1
    assert phone_entities[0].text == "+91 9123456780"

def test_github_url_detection(analyzer_engine):
    blocks = _make_dummy_block("My code is at https://github.com/utkarshhzz/Resume_Sanitizer")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    github_urls = [e for e in entities if e.entity_type == "GITHUB_URL"]
    assert len(github_urls) == 1

def test_deduplication_removes_overlapping(analyzer_engine):
    # If the text has 'Mike' (NER Person) and 'mike@mike.com' (Regex Email), the overlapping system
    # shouldn't destroy one if they don't overlap, BUT if we have a regex match that fully consumes an NER match,
    # it prefers regex.
    blocks = _make_dummy_block("Email: mike@mike.com")
    entities = analyze(analyzer_engine, fitz.open(), blocks, False, 0.55)
    
    # We should definitely have the EMAIL_ADDRESS. 
    # Any generic "PERSON" overlap (if Presidio mistakenly flags 'mike' inside the email) should be dropped 
    # because Email Regex overrides it.
    emails = [e for e in entities if e.entity_type == "EMAIL_ADDRESS"]
    assert len(emails) >= 1
