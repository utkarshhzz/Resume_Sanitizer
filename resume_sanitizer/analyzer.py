from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from resume_sanitizer.config import settings
from resume_sanitizer.models import PIIEntity, PageTextBlock

logger = logging.getLogger(__name__)

# --- LAYER 1: REGEX PATTERNS ---

@dataclass
class CustomEntityContext:
    entity: str
    patterns: list[Pattern]
    context: list[str]

# Defining our highly-accurate Indian and International regex patterns
REGEX_DEFINITIONS = [
    CustomEntityContext(
        entity="EMAIL_ADDRESS",
        patterns=[Pattern("email_regex", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", 0.95)],
        context=["email", "e-mail", "mail"]
    ),
    CustomEntityContext(
        entity="PHONE_NUMBER",
        patterns=[
            Pattern("indian_mobile", r"(\+?91[\-\s]?)?[6-9]\d{9}", 0.90),
            Pattern("international", r"(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}", 0.85)
        ],
        context=["phone", "mobile", "cell", "tel", "contact"]
    ),
    CustomEntityContext(
        entity="LINKEDIN_URL",
        patterns=[Pattern("linkedin_regex", r"(https?://)?(www\.)?linkedin\.com/(in|pub|profile)/[A-Za-z0-9\-_%]+", 0.98)],
        context=[]
    ),
    CustomEntityContext(
        entity="GITHUB_URL",
        patterns=[Pattern("github_regex", r"(https?://)?(www\.)?github\.com/[A-Za-z0-9\-_.]+", 0.98)],
        context=[]
    ),
    CustomEntityContext(
        entity="PAN_CARD",
        patterns=[Pattern("pan_regex", r"[A-Z]{5}[0-9]{4}[A-Z]", 0.95)],
        context=["pan", "tax"]
    ),
    CustomEntityContext(
        entity="AADHAAR_NUMBER",
        patterns=[Pattern("aadhaar_regex", r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", 0.95)],
        context=["aadhaar", "uidai"]
    ),
    CustomEntityContext(
        entity="PINCODE_IN",
        patterns=[Pattern("pincode_regex", r"\b[1-9][0-9]{5}\b", 0.40)],
        context=["pincode", "pin", "postal", "zip"]
    ),
    CustomEntityContext(
        entity="VOTER_ID_IN",
        patterns=[Pattern("voter_regex", r"[A-Z]{3}[0-9]{7}", 0.88)],
        context=["voter", "epic"]
    ),
    CustomEntityContext(
        entity="PASSPORT_IN",
        patterns=[Pattern("passport_regex", r"[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]", 0.90)],
        context=["passport"]
    ),
    CustomEntityContext(
        entity="IP_ADDRESS",
        patterns=[Pattern("ip_regex", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.85)],
        context=["ip", "address"]
    ),
    CustomEntityContext(
        entity="DATE_OF_BIRTH",
        # Matches DD-MM-YYYY, DD/MM/YYYY, etc.
        patterns=[Pattern("dob_regex", r"\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b", 0.40)],
        context=["dob", "date of birth", "born", "birth"]
    ),
    CustomEntityContext(
        entity="BANK_ACCOUNT_IN",
        patterns=[Pattern("bank_acc_regex", r"\b\d{9,18}\b", 0.30)],
        context=["account", "acc no", "bank", "ac/no"]
    ),
    CustomEntityContext(
        entity="IFSC_CODE",
        patterns=[Pattern("ifsc_regex", r"[A-Z]{4}0[A-Z0-9]{6}", 0.95)],
        context=["ifsc", "rtgs", "neft"]
    ),
]


def build_analyzer_engine() -> AnalyzerEngine:
    """
    Initializes the Microsoft Presidio engine with our custom regex rules (Layer 1)
    and spaCy NLP engine (Layer 2).
    """
    # Configure the NLP Engine (Layer 2)
    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": settings.SPACY_MODEL}],
    }
    
    if settings.USE_ONNX_NER:
        logger.warning("ONNX NER requested but not yet implemented. Falling back to spaCy.")
        # Blueprint: Build TransformersNlpEngine with ORTModelForTokenClassification
    
    try:
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
    except Exception as e:
        logger.error(f"Failed to load NLP engine. Did you run 'python -m spacy download {settings.SPACY_MODEL}'? Error: {e}")
        raise

    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["en"],
    )

    # Register custom regex recognizers (Layer 1)
    for defn in REGEX_DEFINITIONS:
        recognizer = PatternRecognizer(
            supported_entity=defn.entity,
            patterns=defn.patterns,
            context=defn.context,
        )
        analyzer.registry.add_recognizer(recognizer)

    return analyzer


# --- LAYER 3: CONTEXT & STRUCTURAL HEURISTICS ---

def detect_largest_font_name(doc: fitz.Document) -> PIIEntity | None:
    """
    Heuristic: The largest text on the top half of the first page of a resume
    is almost always the candidate's name.
    """
    if doc.page_count == 0:
        return None
        
    page = doc[0]
    rect = page.rect
    half_height = rect.height / 2.0
    
    text_dict = page.get_text("dict")
    
    max_size = 0.0
    name_text = ""
    name_start = -1
    
    # We must also ensure we don't accidentally grab a giant "RESUME" header
    excluded_keywords = {"resume", "curriculum vitae", "cv", "profile", "summary", "experience", "education", "skills"}
    
    # We need to simulate finding the offset in the raw concatenated text
    # This is a bit tricky since PyMuPDF's get_text("text") might format slightly differently 
    # than concatenated spans. So we search for the string later.
    
    for block in text_dict.get("blocks", []):
        if "lines" not in block: continue
        for line in block["lines"]:
            for span in line["spans"]:
                y0 = span["bbox"][1]
                size = span["size"]
                text = span["text"].strip()
                
                if y0 < half_height and len(text) > 3:
                    if text.lower() not in excluded_keywords:
                        if size > max_size:
                            max_size = size
                            name_text = text

    if name_text:
        # To get the start/end offset, we look it up in the raw page text
        full_text = page.get_text("text")
        start_idx = full_text.find(name_text)
        if start_idx != -1:
            return PIIEntity(
                entity_type="PERSON",
                text=name_text,
                score=0.72,
                page=1, # 1-indexed
                detection_layer="heuristic",
                start=start_idx,
                end=start_idx + len(name_text)
            )
            
    return None

def detect_label_triggered_pii(blocks: list[PageTextBlock]) -> list[PIIEntity]:
    """
    Heuristic: Look for specific labels like "Phone:" or "DOB:" and aggressively 
    capture the text immediately following it, even if NLP failed.
    """
    results: list[PIIEntity] = []
    
    # Tuple of (Regex to find label, Entity Type, Confidence Score, Regex to capture value)
    triggers = [
        (r"(?i)\b(?:phone|tel|mobile|cell)\s*[:-]\s*", "PHONE_NUMBER", 0.85, r"([+\d\s\-\(\)]{8,15})"),
        (r"(?i)\b(?:email|e-mail)\s*[:-]\s*", "EMAIL_ADDRESS", 0.85, r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"),
        (r"(?i)\b(?:github|git)\s*[:-]\s*", "GITHUB_URL", 0.90, r"([^\s\n]+)"),
        (r"(?i)\b(?:linkedin)\s*[:-]\s*", "LINKEDIN_URL", 0.90, r"([^\s\n]+)"),
        (r"(?i)\b(?:dob|date of birth)\s*[:-]\s*", "DATE_OF_BIRTH", 0.88, r"([^\n]{6,12})"),
        # Location/Address is tricky, we capture the rest of the line
        (r"(?i)\b(?:address|location|city)\s*[:-]\s*", "LOCATION", 0.75, r"([^\n]+)"), 
    ]
    
    for block in blocks:
        text = block.text
        for label_pattern, entity_type, score, value_pattern in triggers:
            # Combine them: Look for Label followed by Value
            full_pattern = label_pattern + value_pattern
            for match in re.finditer(full_pattern, text):
                value_text = match.group(1).strip()
                if not value_text: continue
                
                # The start offset of the *value* (group 1)
                start_offset = match.start(1) 
                
                results.append(
                    PIIEntity(
                        entity_type=entity_type,
                        text=value_text,
                        score=score,
                        page=block.page_number,
                        detection_layer="heuristic",
                        start=start_offset,
                        end=start_offset + len(value_text)
                    )
                )
    return results


# --- MASTER ORCHESTRATOR ---

def analyze(analyzer: AnalyzerEngine, doc: fitz.Document, blocks: list[PageTextBlock], ocr_used: bool, min_confidence: float) -> list[PIIEntity]:
    """
    The master analysis orchestrator. Runs all 3 layers of detection and deduplicates overlapping results.
    """
    all_entities: list[PIIEntity] = []
    
    # Layer 1 (Regex) + Layer 2 (Presidio NLP)
    # We purposefully exclude "ORG", "LOCATION" by default so we don't accidentally erase 
    # colleges (Indian Institute of Technology) or technical skills (Microsoft Azure).
    entities_to_find = [d.entity for d in REGEX_DEFINITIONS] + ["PERSON", "US_SSN"]

    for block in blocks:
        # Analyze using Microsoft Presidio
        results: list[RecognizerResult] = analyzer.analyze(
            text=block.text,
            language="en",
            entities=entities_to_find
        )
        
        for r in results:
            if r.score < min_confidence: continue
            
            # Determine layer based on entity type. If it's one of our custom ones, it was Regex.
            layer = "regex" if any(r.entity_type == d.entity for d in REGEX_DEFINITIONS) else "presidio_ner"
            
            all_entities.append(
                PIIEntity(
                    entity_type=r.entity_type,
                    text=block.text[r.start:r.end],
                    score=r.score,
                    page=block.page_number,
                    detection_layer=layer,
                    start=r.start,
                    end=r.end
                )
            )

    # Layer 3 (Heuristics)
    if not ocr_used: # Largest font heuristic only works reliably on digital PDFs
        largest_font_pii = detect_largest_font_name(doc)
        if largest_font_pii and largest_font_pii.score >= min_confidence:
            all_entities.append(largest_font_pii)
            
    heuristic_label_piis = detect_label_triggered_pii(blocks)
    for pii in heuristic_label_piis:
        if pii.score >= min_confidence:
            all_entities.append(pii)


    # Deduplication
    # A single string like "john.doe@email.com" might be flagged as both a PERSON (by NER) and an EMAIL_ADDRESS (by Regex)
    # We want to keep the one with the higher score, or default to the more specific Regex.
    
    deduped: list[PIIEntity] = []
    
    # Group by page first to avoid cross-page confusion
    from itertools import groupby
    all_entities.sort(key=lambda x: x.page)
    
    for page_num, page_entities_iter in groupby(all_entities, key=lambda x: x.page):
        page_entities = list(page_entities_iter)
        # Sort by start offset
        page_entities.sort(key=lambda x: x.start)
        
        keep: list[PIIEntity] = []
        for current in page_entities:
            overlapping = False
            for i, kept in enumerate(keep):
                # Check for overlap: start_a < end_b and start_b < end_a
                if current.start < kept.end and kept.start < current.end:
                    overlapping = True
                    # If current has a strictly higher score, replace the kept one
                    if current.score > kept.score:
                        keep[i] = current
                    # If scores are equal, prefer regex over NER (regex is usually more precise)
                    elif current.score == kept.score and current.detection_layer == "regex" and kept.detection_layer != "regex":
                        keep[i] = current
                    break # Already found an overlap, don't check rest
                    
            if not overlapping:
                keep.append(current)
                
        deduped.extend(keep)

    return deduped
