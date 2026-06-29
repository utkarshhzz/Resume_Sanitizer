from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

import fitz  # PyMuPDF
from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider

from resume_sanitizer.config import settings
from resume_sanitizer.models import PIIEntity, PageTextBlock
from resume_sanitizer.candidate import (
    build_candidate_profile,
    filter_to_candidate_person_only,
    find_candidate_name_occurrences,
    is_platform_name,
)

logger = logging.getLogger(__name__)


# --- LAYER 1: REGEX PATTERNS ---

@dataclass
class CustomEntityContext:
    entity: str
    patterns: list[Pattern]
    context: list[str]


# Ordered by specificity — higher base scores for precise patterns.
# Presidio's context boost (+0.35) only fires when context words appear nearby.
REGEX_DEFINITIONS = [
    # HIGH PRECISION
    CustomEntityContext(
        entity="EMAIL_ADDRESS",
        patterns=[Pattern("email_regex", r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", 0.95)],
        context=["email", "e-mail", "mail"]
    ),
    CustomEntityContext(
        entity="PHONE_NUMBER",
        patterns=[
            Pattern("indian_mobile", r"(\+?91[\-\s]?)?[6-9]\d{9}\b", 0.90),
            Pattern("international", r"(\+?\d{1,3}[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}", 0.85)
        ],
        context=["phone", "mobile", "cell", "tel", "contact", "call"]
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
    # Pipe-separated social links on one line (github.com/x | linkedin.com/in/y)
    CustomEntityContext(
        entity="SOCIAL_LINK_GROUP",
        patterns=[Pattern(
            "pipe_social_links",
            r"(?:https?://)?(?:www\.)?(?:github\.com|linkedin\.com|gitlab\.com|bitbucket\.org)/"
            r"[^\s|•·]+(?:\s*[|•·]\s*(?:https?://)?(?:www\.)?"
            r"(?:github\.com|linkedin\.com|gitlab\.com|bitbucket\.org)/[^\s|•·]+)+",
            0.99,
        )],
        context=[],
    ),
    CustomEntityContext(
        entity="SOCIAL_MEDIA_URL",
        patterns=[
            Pattern("twitter_regex", r"(https?://)?(www\.)?(twitter\.com|x\.com)/[A-Za-z0-9_]+", 0.95),
            Pattern("instagram_regex", r"(https?://)?(www\.)?instagram\.com/[A-Za-z0-9_.]+", 0.95),
            Pattern("facebook_regex", r"(https?://)?(www\.)?facebook\.com/[A-Za-z0-9_.]+", 0.95),
            Pattern("telegram_regex", r"(https?://)?t\.me/[A-Za-z0-9_]+", 0.95),
            Pattern("medium_regex", r"(https?://)?(www\.)?medium\.com/@?[A-Za-z0-9_.]+", 0.90),
            Pattern("stackoverflow_regex", r"(https?://)?(www\.)?stackoverflow\.com/users/[0-9]+", 0.90),
            Pattern("behance_regex", r"(https?://)?(www\.)?behance\.net/[A-Za-z0-9_.]+", 0.90),
            Pattern("dribbble_regex", r"(https?://)?(www\.)?dribbble\.com/[A-Za-z0-9_.]+", 0.90),
            Pattern("codepen_regex", r"(https?://)?(www\.)?codepen\.io/[A-Za-z0-9_.]+", 0.90),
        ],
        context=[]
    ),
    # Catch-all URL — low base score, boosted by context words like "portfolio"
    CustomEntityContext(
        entity="PERSONAL_URL",
        patterns=[
            Pattern("general_url", r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+", 0.60),
        ],
        context=["portfolio", "website", "blog", "site", "url", "link", "personal"]
    ),
    CustomEntityContext(
        entity="PAN_CARD",
        patterns=[Pattern("pan_regex", r"\b[A-Z]{5}[0-9]{4}[A-Z]\b", 0.95)],
        context=["pan", "tax", "income tax", "permanent account"]
    ),
    CustomEntityContext(
        entity="AADHAAR_NUMBER",
        patterns=[Pattern("aadhaar_regex", r"\b[2-9]{1}[0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b", 0.95)],
        context=["aadhaar", "uidai", "uid"]
    ),
    CustomEntityContext(
        entity="IFSC_CODE",
        patterns=[Pattern("ifsc_regex", r"\b[A-Z]{4}0[A-Z0-9]{6}\b", 0.95)],
        context=["ifsc", "rtgs", "neft"]
    ),
    CustomEntityContext(
        entity="VOTER_ID_IN",
        patterns=[Pattern("voter_regex", r"\b[A-Z]{3}[0-9]{7}\b", 0.88)],
        context=["voter", "epic", "election"]
    ),
    CustomEntityContext(
        entity="PASSPORT_IN",
        patterns=[Pattern("passport_regex", r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b", 0.90)],
        context=["passport"]
    ),

    # MEDIUM PRECISION — need context words nearby
    CustomEntityContext(
        entity="IP_ADDRESS",
        patterns=[Pattern("ip_regex", r"\b(?:\d{1,3}\.){3}\d{1,3}\b", 0.85)],
        context=["ip", "address", "server"]
    ),
    CustomEntityContext(
        entity="DATE_OF_BIRTH",
        # Low base score — dates are everywhere in resumes. Only fires with DOB context.
        patterns=[Pattern("dob_regex", r"\b(0?[1-9]|[12]\d|3[01])[\/\-](0?[1-9]|1[0-2])[\/\-](19|20)\d{2}\b", 0.35)],
        context=["dob", "date of birth", "born", "birth", "birthday"]
    ),

    # LOW PRECISION — extremely high false-positive risk without context
    CustomEntityContext(
        entity="PINCODE_IN",
        # Base 0.25 + context boost 0.35 = 0.60 (above 0.55 threshold only with context)
        patterns=[Pattern("pincode_regex", r"\b[1-9][0-9]{5}\b", 0.25)],
        context=["pincode", "pin code", "postal code", "zip code", "postal"]
    ),
    CustomEntityContext(
        entity="BANK_ACCOUNT_IN",
        # 11+ digits avoids matching 10-digit phone numbers
        patterns=[Pattern("bank_acc_regex", r"\b\d{11,18}\b", 0.25)],
        context=["account", "acc no", "bank", "ac/no", "account number", "a/c"]
    ),
]


def build_analyzer_engine() -> AnalyzerEngine:
    """Initialize Presidio with custom regex (Layer 1) + spaCy NLP (Layer 2)."""
    if settings.OFFLINE_MODE:
        os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
        os.environ.setdefault("HF_DATASETS_OFFLINE", "1")
        os.environ.setdefault("HF_HUB_OFFLINE", "1")

    configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": settings.SPACY_MODEL}],
    }

    try:
        provider = NlpEngineProvider(nlp_configuration=configuration)
        nlp_engine = provider.create_engine()
    except Exception as e:
        logger.error(f"Failed to load NLP engine. Run: python -m spacy download {settings.SPACY_MODEL}. Error: {e}")
        raise

    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])

    for defn in REGEX_DEFINITIONS:
        recognizer = PatternRecognizer(
            supported_entity=defn.entity,
            patterns=defn.patterns,
            context=defn.context,
        )
        analyzer.registry.add_recognizer(recognizer)

    return analyzer


# --- LAYER 3: CONTEXT & STRUCTURAL HEURISTICS ---

SECTION_HEADERS = {
    "CONTACT": ["contact", "contact information", "contact details", "personal details", "personal information", "personal info"],
    "SUMMARY": ["summary", "objective", "about me", "professional summary", "career objective", "profile"],
    "EXPERIENCE": ["experience", "work experience", "professional experience", "employment", "employment history", "work history"],
    "EDUCATION": ["education", "academic", "academics", "qualifications", "educational qualifications"],
    "SKILLS": ["skills", "technical skills", "technologies", "competencies", "tools", "proficiency"],
    "PROJECTS": ["projects", "personal projects", "academic projects", "key projects"],
    "CERTIFICATIONS": ["certifications", "certificates", "licenses", "training"],
    "AWARDS": ["awards", "honors", "achievements", "accomplishments"],
}

# Always redacted regardless of section
ALWAYS_REDACT_ENTITY_TYPES = frozenset({
    "EMAIL_ADDRESS", "PHONE_NUMBER", "LINKEDIN_URL", "GITHUB_URL", "SOCIAL_MEDIA_URL",
    "SOCIAL_LINK_GROUP", "PERSONAL_URL", "PAN_CARD", "AADHAAR_NUMBER", "IFSC_CODE",
    "VOTER_ID_IN", "PASSPORT_IN", "US_SSN", "IP_ADDRESS", "DATE_OF_BIRTH",
    "BANK_ACCOUNT_IN", "PINCODE_IN",
})

# Sections where NER names should NOT be redacted (skills, projects, etc.)
PROTECTED_CONTENT_SECTIONS = frozenset({"SKILLS", "PROJECTS", "EDUCATION", "CERTIFICATIONS", "AWARDS"})

URL_ENTITY_TYPES = frozenset({
    "LINKEDIN_URL", "GITHUB_URL", "SOCIAL_MEDIA_URL", "SOCIAL_LINK_GROUP", "PERSONAL_URL",
})

# Tech/tools that NER falsely flags — never redact these
TECH_SKILL_WHITELIST = frozenset({
    "kafka", "supabase", "redis", "postgresql", "postgres", "mongodb", "mysql", "mariadb",
    "docker", "kubernetes", "k8s", "react", "reactjs", "angular", "vue", "vuejs", "nextjs",
    "nodejs", "node.js", "python", "java", "javascript", "typescript", "golang", "rust",
    "aws", "azure", "gcp", "terraform", "ansible", "jenkins", "gitlab", "graphql",
    "fastapi", "django", "flask", "spring", "hibernate", "elasticsearch", "rabbitmq",
    "celery", "nginx", "apache", "linux", "unix", "windows", "macos", "android", "ios",
    "swift", "kotlin", "scala", "hadoop", "spark", "airflow", "dbt", "snowflake",
    "databricks", "tableau", "powerbi", "pandas", "numpy", "scikit-learn", "pytorch",
    "tensorflow", "opencv", "selenium", "cypress", "jest", "pytest", "maven", "gradle",
    "npm", "yarn", "webpack", "vite", "tailwind", "bootstrap", "sass", "less",
    "microservices", "rest", "restful", "grpc", "websocket", "oauth", "jwt",
    "ci/cd", "devops", "agile", "scrum", "jira", "confluence", "figma", "postman",
    "swagger", "openapi", "firebase", "heroku", "vercel", "netlify", "cloudflare",
    "datadog", "sentry", "prometheus", "grafana", "splunk", "elastic", "kibana",
    "cassandra", "dynamodb", "neo4j", "sqlite", "oracle", "sql", "nosql", "html",
    "css", "sass", "xml", "json", "yaml", "toml", "markdown", "latex",
})

_PIPE_CHARS = frozenset("|•·")


def _entity_absolute_offset(blocks: list[PageTextBlock], entity: PIIEntity) -> int:
    """Map a page-local entity offset to the concatenated multi-page text offset."""
    offset = 0
    for block in blocks:
        if block.page_number == entity.page:
            return offset + entity.start
        offset += len(block.text) + 2
    return entity.start


def _section_for_offset(sections: dict[str, tuple[int, int]], abs_offset: int) -> str | None:
    for name, (start, end) in sections.items():
        if start <= abs_offset < end:
            return name
    return None


def _is_whitelisted_skill(text: str) -> bool:
    normalized = text.strip().lower().rstrip(".,;:")
    if normalized in TECH_SKILL_WHITELIST:
        return True
    for part in re.split(r"[,|/•·]", normalized):
        token = part.strip()
        if token and token not in TECH_SKILL_WHITELIST:
            return False
    return bool(normalized)


def merge_pipe_delimited_urls(entities: list[PIIEntity], blocks: list[PageTextBlock]) -> list[PIIEntity]:
    """Merge adjacent URL entities separated by | • into one span."""
    block_map = {b.page_number: b for b in blocks}
    by_page: dict[int, list[PIIEntity]] = {}
    other: list[PIIEntity] = []

    for entity in entities:
        if entity.entity_type in URL_ENTITY_TYPES:
            by_page.setdefault(entity.page, []).append(entity)
        else:
            other.append(entity)

    merged: list[PIIEntity] = list(other)
    for page_num, page_entities in by_page.items():
        page_entities.sort(key=lambda e: e.start)
        block = block_map.get(page_num)
        if not block:
            merged.extend(page_entities)
            continue

        i = 0
        while i < len(page_entities):
            current = page_entities[i]
            group_start = current.start
            group_end = current.end
            group_score = current.score
            group_layer = current.detection_layer
            j = i + 1

            while j < len(page_entities):
                nxt = page_entities[j]
                between = block.text[group_end:nxt.start]
                if between.strip() and all(c in _PIPE_CHARS or c.isspace() for c in between):
                    group_end = nxt.end
                    group_score = max(group_score, nxt.score)
                    j += 1
                else:
                    break

            merged.append(PIIEntity(
                entity_type="SOCIAL_LINK_GROUP" if j > i + 1 else current.entity_type,
                text=block.text[group_start:group_end],
                score=group_score,
                page=page_num,
                detection_layer=group_layer,
                start=group_start,
                end=group_end,
            ))
            i = j

    return merged


def filter_false_positives(
    entities: list[PIIEntity],
    blocks: list[PageTextBlock],
    sections: dict[str, tuple[int, int]],
) -> list[PIIEntity]:
    """Drop NER/heuristic noise in skills/projects and whitelisted tech terms."""
    filtered: list[PIIEntity] = []

    for entity in entities:
        text = entity.text.strip()
        if not text:
            continue

        if _is_whitelisted_skill(text):
            continue

        if is_platform_name(text):
            continue

        abs_offset = _entity_absolute_offset(blocks, entity)
        section = _section_for_offset(sections, abs_offset)

        if section in PROTECTED_CONTENT_SECTIONS:
            if entity.entity_type not in ALWAYS_REDACT_ENTITY_TYPES:
                continue
            if entity.entity_type in URL_ENTITY_TYPES and not re.search(
                r"(github\.com|linkedin\.com|gitlab\.com|bitbucket\.org|@|https?://)", text, re.I
            ):
                continue

        filtered.append(entity)

    return filtered


def detect_resume_sections(blocks: list[PageTextBlock]) -> dict[str, tuple[int, int]]:
    """Identify resume section boundaries by scanning for common header keywords."""
    sections: dict[str, tuple[int, int]] = {}
    full_text = "\n\n".join(b.text for b in blocks)
    lines = full_text.split("\n")

    found_sections: list[tuple[str, int]] = []
    current_offset = 0
    for line in lines:
        stripped = line.strip()
        if stripped and len(stripped) < 50:
            normalized = stripped.lower().rstrip(":")
            normalized = re.sub(r'^[\-•|►▸▹●○◆◇→\s]+', '', normalized).strip()
            for section_name, keywords in SECTION_HEADERS.items():
                if normalized in keywords:
                    found_sections.append((section_name, current_offset))
                    break
        current_offset += len(line) + 1

    for i, (name, start) in enumerate(found_sections):
        end = found_sections[i + 1][1] if i + 1 < len(found_sections) else len(full_text)
        sections[name] = (start, end)

    # Implicit CONTACT: text before the first section header
    if "CONTACT" not in sections and found_sections:
        first_section_start = found_sections[0][1]
        if first_section_start > 20:
            sections["CONTACT"] = (0, first_section_start)
    elif not found_sections and blocks:
        sections["CONTACT"] = (0, min(500, len(blocks[0].text)))

    return sections


def detect_largest_font_name(doc: fitz.Document) -> PIIEntity | None:
    """Heuristic: largest text in top half of page 1 is the candidate's name."""
    if doc.page_count == 0:
        return None

    page = doc[0]
    half_height = page.rect.height / 2.0
    text_dict = page.get_text("dict")

    excluded_keywords = {
        "resume", "curriculum vitae", "cv", "profile", "summary",
        "experience", "education", "skills", "objective", "about me",
        "contact", "personal", "professional"
    }

    # Find max font size in top half
    max_size = 0.0
    for block in text_dict.get("blocks", []):
        if "lines" not in block:
            continue
        for line in block["lines"]:
            for span in line["spans"]:
                y0 = span["bbox"][1]
                text = span["text"].strip()
                if y0 < half_height and len(text) > 1 and text.lower() not in excluded_keywords:
                    if span["size"] > max_size:
                        max_size = span["size"]

    if max_size == 0:
        return None

    # Collect all spans at max size on the first matching line (handles multi-span names)
    name_parts: list[str] = []
    for block in text_dict.get("blocks", []):
        if "lines" not in block:
            continue
        for line in block["lines"]:
            line_parts = []
            for span in line["spans"]:
                y0 = span["bbox"][1]
                text = span["text"].strip()
                if (y0 < half_height
                    and abs(span["size"] - max_size) < 0.5
                    and len(text) > 1
                    and text.lower() not in excluded_keywords):
                    line_parts.append(text)
            if line_parts:
                name_parts.extend(line_parts)
                break

    if not name_parts:
        return None

    name_text = " ".join(name_parts).strip()
    if len(name_text) < 3 or len(name_text) > 60:
        return None

    full_text = page.get_text("text")
    start_idx = full_text.find(name_text)
    if start_idx == -1 and name_parts:
        start_idx = full_text.find(name_parts[0])
        if start_idx != -1:
            name_text = name_parts[0]
            for part in name_parts[1:]:
                next_idx = full_text.find(part, start_idx + len(name_text))
                if next_idx != -1:
                    name_text = full_text[start_idx:next_idx + len(part)]

    if start_idx != -1:
        return PIIEntity(
            entity_type="PERSON", text=name_text, score=0.72,
            page=1, detection_layer="heuristic",
            start=start_idx, end=start_idx + len(name_text)
        )
    return None


def detect_label_triggered_pii(blocks: list[PageTextBlock]) -> list[PIIEntity]:
    """Safety net: capture PII after labels like 'Phone:', 'Email:', etc."""
    results: list[PIIEntity] = []

    triggers = [
        (r"(?i)\b(?:phone|tel|mobile|cell|contact\s*no|ph)\s*[:\-\.]\s*", "PHONE_NUMBER", 0.88, r"([+\d\s\-\(\)]{7,18})"),
        (r"(?i)\b(?:email|e-mail|mail\s*id)\s*[:\-\.]\s*", "EMAIL_ADDRESS", 0.88, r"([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})"),
        (r"(?i)\b(?:github|git)\s*[:\-\.]\s*", "GITHUB_URL", 0.92, r"([^\s\n]+)"),
        (r"(?i)\b(?:linkedin)\s*[:\-\.]\s*", "LINKEDIN_URL", 0.92, r"([^\s\n]+)"),
        (r"(?i)\b(?:dob|date of birth)\s*[:\-\.]\s*", "DATE_OF_BIRTH", 0.88, r"([^\n]{6,15})"),
        (r"(?i)\b(?:website|portfolio|blog|site)\s*[:\-\.]\s*", "PERSONAL_URL", 0.85, r"([^\s\n]+)"),
        (r"(?i)\b(?:twitter|instagram|facebook|telegram)\s*[:\-\.]\s*", "SOCIAL_MEDIA_URL", 0.90, r"([^\s\n]+)"),
        (r"(?i)\b(?:skype|discord)\s*[:\-\.]\s*", "SOCIAL_MEDIA_URL", 0.85, r"([^\s\n]+)"),
    ]

    for block in blocks:
        text = block.text
        for label_pattern, entity_type, score, value_pattern in triggers:
            full_pattern = label_pattern + value_pattern
            for match in re.finditer(full_pattern, text):
                value_text = match.group(1).strip()
                if not value_text:
                    continue
                start_offset = match.start(1)
                results.append(PIIEntity(
                    entity_type=entity_type, text=value_text, score=score,
                    page=block.page_number, detection_layer="heuristic",
                    start=start_offset, end=start_offset + len(value_text)
                ))
    return results


# --- MASTER ORCHESTRATOR ---

def analyze(
    analyzer: AnalyzerEngine,
    doc: fitz.Document,
    blocks: list[PageTextBlock],
    ocr_used: bool,
    min_confidence: float
) -> list[PIIEntity]:
    """Run all 3 detection layers, deduplicate, and filter false positives."""
    all_entities: list[PIIEntity] = []

    # Layer 1 (Regex) + Layer 2 (Presidio NLP)
    # Exclude LOCATION — resumes have city names in EXPERIENCE that aren't personal PII
    entities_to_find = [d.entity for d in REGEX_DEFINITIONS] + ["PERSON", "US_SSN"]

    for block in blocks:
        results: list[RecognizerResult] = analyzer.analyze(
            text=block.text, language="en", entities=entities_to_find
        )
        for r in results:
            if r.score < min_confidence:
                continue
            layer = "regex" if any(r.entity_type == d.entity for d in REGEX_DEFINITIONS) else "presidio_ner"
            all_entities.append(PIIEntity(
                entity_type=r.entity_type, text=block.text[r.start:r.end],
                score=r.score, page=block.page_number,
                detection_layer=layer, start=r.start, end=r.end
            ))

    # Layer 3 (Heuristics)
    header_name: PIIEntity | None = None
    if not ocr_used:
        header_name = detect_largest_font_name(doc)
        if header_name and header_name.score >= min_confidence:
            all_entities.append(header_name)

    for pii in detect_label_triggered_pii(blocks):
        if pii.score >= min_confidence:
            all_entities.append(pii)

    # Section-aware confidence boosting
    sections = detect_resume_sections(blocks)
    contact_section = sections.get("CONTACT")
    experience_section = sections.get("EXPERIENCE")

    boosted_entities: list[PIIEntity] = []
    for entity in all_entities:
        new_score = entity.score

        if contact_section:
            full_text_offset = 0
            for b in blocks:
                if b.page_number == entity.page:
                    entity_abs_start = full_text_offset + entity.start
                    if contact_section[0] <= entity_abs_start < contact_section[1]:
                        new_score = min(1.0, entity.score + 0.10)
                    break
                full_text_offset += len(b.text) + 2

        if experience_section and entity.entity_type == "PERSON":
            full_text_offset = 0
            for b in blocks:
                if b.page_number == entity.page:
                    entity_abs_start = full_text_offset + entity.start
                    if experience_section[0] <= entity_abs_start < experience_section[1]:
                        new_score = entity.score - 0.15
                    break
                full_text_offset += len(b.text) + 2

        if new_score >= min_confidence:
            boosted_entities.append(PIIEntity(
                entity_type=entity.entity_type, text=entity.text,
                score=new_score, page=entity.page,
                detection_layer=entity.detection_layer,
                start=entity.start, end=entity.end,
            ))

    all_entities = boosted_entities

    # Merge pipe-separated URL groups
    all_entities = merge_pipe_delimited_urls(all_entities, blocks)

    # Deduplication — keep highest score for overlapping entities
    deduped: list[PIIEntity] = []
    from itertools import groupby
    all_entities.sort(key=lambda x: x.page)

    for page_num, page_entities_iter in groupby(all_entities, key=lambda x: x.page):
        page_entities = list(page_entities_iter)
        page_entities.sort(key=lambda x: x.start)

        keep: list[PIIEntity] = []
        for current in page_entities:
            overlapping = False
            for i, kept in enumerate(keep):
                if current.start < kept.end and kept.start < current.end:
                    overlapping = True
                    if current.score > kept.score:
                        keep[i] = current
                    elif current.score == kept.score and current.detection_layer == "regex":
                        keep[i] = current
                    break
            if not overlapping:
                keep.append(current)
        deduped.extend(keep)

    # Candidate-only name redaction (drop platform names, colleague names, school cities)
    profile = build_candidate_profile(blocks, sections, deduped, header_name)
    deduped = filter_to_candidate_person_only(deduped, profile, header_name)
    if profile:
        deduped.extend(find_candidate_name_occurrences(blocks, profile, min_confidence))
        # Re-dedupe after adding name occurrences
        deduped.sort(key=lambda x: (x.page, x.start))
        final: list[PIIEntity] = []
        for current in deduped:
            overlap = False
            for i, kept in enumerate(final):
                if current.page == kept.page and current.start < kept.end and kept.start < current.end:
                    overlap = True
                    if current.score > kept.score:
                        final[i] = current
                    break
            if not overlap:
                final.append(current)
        deduped = final

    # False-positive filter (skills whitelist, section-aware)
    return filter_false_positives(deduped, blocks, sections)
