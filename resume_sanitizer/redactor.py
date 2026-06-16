from __future__ import annotations

import io
import logging
import re
from collections import defaultdict

import fitz  # PyMuPDF

from resume_sanitizer.config import settings
from resume_sanitizer.models import PIIEntity, PageTextBlock, RedactionTarget
from resume_sanitizer.utils import expand_rect, merge_overlapping_rects, normalize_text_for_search

logger = logging.getLogger(__name__)

SEPARATOR_SEARCH_CHARS = ("|", "•", "·")
SEPARATOR_PROXIMITY_PX = 14.0

# URL text must contain a real domain path — never redact bare words like "LinkedIn"
_IDENTITY_URL_PATTERN = re.compile(
    r"(github\.com/|linkedin\.com/|gitlab\.com/|bitbucket\.org/|https?://|mailto:)",
    re.IGNORECASE,
)


def _rects_from_word_blocks(
    page_block: PageTextBlock,
    entity: PIIEntity,
    page_width: float,
    page_height: float,
) -> list[tuple[float, float, float, float]]:
    """Map character offsets to word bounding boxes — precise, no global page search."""
    rects: list[tuple[float, float, float, float]] = []
    current_offset = 0
    for w in page_block.words:
        word_start = page_block.text.find(w.text, current_offset)
        if word_start == -1:
            continue
        word_end = word_start + len(w.text)
        current_offset = word_end
        if max(word_start, entity.start) < min(word_end, entity.end):
            rects.append(expand_rect(
                (w.x0, w.y0, w.x1, w.y1),
                settings.REDACTION_PADDING_PX,
                page_width,
                page_height,
            ))
    return rects


def _is_redactable_url(text: str) -> bool:
    """Only redact actual profile/identity URLs, not platform names in prose."""
    return bool(_IDENTITY_URL_PATTERN.search(text))

# 🎓 Teacher Note: Domains that ALWAYS reveal candidate identity.
# If a PDF has a clickable hyperlink to any of these, we sever it
# even if the regex somehow missed the visible text.
IDENTITY_LINK_DOMAINS = [
    "linkedin.com", "github.com", "gitlab.com", "bitbucket.org",
    "twitter.com", "x.com", "instagram.com", "facebook.com",
    "wa.me", "t.me", "telegram.me",
    "medium.com", "dev.to", "hashnode.dev",
    "stackoverflow.com", "stackexchange.com",
    "behance.net", "dribbble.com", "codepen.io",
    "kaggle.com", "leetcode.com", "hackerrank.com", "codeforces.com",
    "youtube.com", "vimeo.com",
    "portfolio", "personal", "blog",
    # Email links
    "mailto:",
]


def _rect_near_any(rect: tuple[float, float, float, float], others: list[tuple[float, float, float, float]], gap: float) -> bool:
    """True if rect is within gap pixels of any rect in others (same-line adjacency)."""
    x0, y0, x1, y1 = rect
    for ox0, oy0, ox1, oy1 in others:
        y_overlap = max(0, min(y1, oy1) - max(y0, oy0))
        same_line = y_overlap > 0 or abs(y0 - oy0) <= 6.0
        if not same_line:
            continue
        h_gap = max(0, max(x0, ox0) - min(x1, ox1))
        if h_gap <= gap:
            return True
    return False


def _collect_separator_rects(
    page: fitz.Page,
    existing_rects: list[tuple[float, float, float, float]],
    page_rect: fitz.Rect,
) -> list[tuple[float, float, float, float]]:
    """Redact orphaned | • between partially-redacted link groups."""
    if not existing_rects:
        return []

    extra: list[tuple[float, float, float, float]] = []
    all_rects = list(existing_rects)

    for char in SEPARATOR_SEARCH_CHARS:
        for quad in page.search_for(char, quads=True):
            r = quad.rect
            candidate = (
                max(0.0, r.x0 - 1),
                max(0.0, r.y0 - 1),
                min(page_rect.width, r.x1 + 1),
                min(page_rect.height, r.y1 + 1),
            )
            if _rect_near_any(candidate, all_rects, SEPARATOR_PROXIMITY_PX):
                extra.append(candidate)
                all_rects.append(candidate)

    return extra


def build_redaction_targets(
    doc: fitz.Document, 
    entities: list[PIIEntity], 
    blocks: list[PageTextBlock], 
    ocr_used: bool
) -> list[RedactionTarget]:
    """
    Translates textual PII entities into physical geometric rectangles (bounding boxes)
    that we need to redact on the PDF pages.
    
    🎓 Teacher Note: This is the trickiest part of the entire system.
    The analyzer found "john@email.com" at character offset 45-59 in the text.
    But to erase it from the PDF, we need its PIXEL COORDINATES (x0, y0, x1, y1).
    
    Digital path: Ask PyMuPDF to search for the text string → it returns coordinates.
    OCR path: We already have coordinates from Tesseract for each word → we map offsets to words.
    """
    targets: list[RedactionTarget] = []

    # Fast lookup for text blocks by page
    block_map = {b.page_number: b for b in blocks}

    for entity in entities:
        # Skip URL entities that are not real links (prevents prose bleed)
        if entity.entity_type in (
            "LINKEDIN_URL", "GITHUB_URL", "SOCIAL_MEDIA_URL",
            "SOCIAL_LINK_GROUP", "PERSONAL_URL",
        ) and not _is_redactable_url(entity.text):
            continue

        # PyMuPDF pages are 0-indexed, but our models use 1-indexed page_numbers
        page_index = entity.page - 1
        
        # Guard against invalid pages
        if page_index < 0 or page_index >= doc.page_count:
            logger.warning(f"Entity page {entity.page} out of bounds.")
            continue
            
        page = doc[page_index]
        page_rect = page.rect
        rects: list[tuple[float, float, float, float]] = []
        page_block = block_map.get(entity.page)

        if page_block:
            # Prefer word-block offset mapping (digital + OCR) — redacts ONLY the matched span
            rects = _rects_from_word_blocks(page_block, entity, page_rect.width, page_rect.height)

        if not rects and not ocr_used:
            # Fallback: exact full-string search only (never prefix — that hits every "LinkedIn" on page)
            search_text = normalize_text_for_search(entity.text)
            if search_text:
                quads = page.search_for(search_text, quads=True)
                for q in quads:
                    r = q.rect
                    rects.append(expand_rect(
                        (r.x0, r.y0, r.x1, r.y1),
                        settings.REDACTION_PADDING_PX,
                        page_rect.width,
                        page_rect.height,
                    ))

        merged_rects = merge_overlapping_rects(rects)

        # Catch leftover | • between link redactions on the same line
        if not ocr_used and merged_rects:
            merged_rects = merge_overlapping_rects(
                merged_rects + _collect_separator_rects(page, merged_rects, page_rect)
            )

        if merged_rects:
            targets.append(RedactionTarget(
                page_number=entity.page,
                entity_type=entity.entity_type,
                original_text=entity.text,
                rects=merged_rects,
                source="ocr" if ocr_used else "digital"
            ))

    return targets


def apply_redactions(doc: fitz.Document, targets: list[RedactionTarget]) -> bytes:
    """
    Applies redactions permanently to the PDF.
    
    🎓 Teacher Note: This is NOT just drawing a white box on top!
    PyMuPDF's redaction system works in 2 steps:
      1. add_redact_annot() — marks an area for deletion (like putting tape over it)
      2. apply_redactions()  — PHYSICALLY REMOVES the text from the PDF binary structure
    
    After apply_redactions(), even if someone opens the PDF in a hex editor,
    the original text bytes are GONE. This is true "deep redaction".
    
    We also scrub:
      - Document metadata (Author, Title, Subject, etc.)
      - XML metadata streams (XMP data)
      - Clickable hyperlinks to social media / email
    """
    # Group targets by page to process page-by-page efficiently
    page_targets = defaultdict(list)
    for t in targets:
        page_targets[t.page_number].append(t)

    # Process EVERY page, even those without text targets
    # (because they might have hyperlinks that need purging)
    for page_index in range(doc.page_count):
        page_number = page_index + 1
        page = doc[page_index]
        target_list = page_targets.get(page_number, [])
        
        # Step 1: Draw the Redaction Annotations for detected PII text
        for target in target_list:
            for rect_coords in target.rects:
                rect_obj = fitz.Rect(*rect_coords)
                # White fill = invisible redaction. The text area becomes blank white space.
                page.add_redact_annot(rect_obj, fill=settings.REDACTION_FILL_COLOR)

        # Step 2: Purge Clickable Hyperlinks BEFORE applying redactions
        # 🎓 Teacher Note: We MUST collect and delete links BEFORE calling
        # apply_redactions(). Why? apply_redactions() physically alters the PDF
        # structure, which corrupts PyMuPDF's internal link cross-reference table.
        # If we call page.get_links() AFTER apply_redactions(), we get
        # "IndexError: list index out of range" because the xref table is stale.
        #
        # The correct order is: mark text → collect links → delete links → apply all at once.
        
        try:
            links = page.get_links()
        except Exception:
            links = []
        
        links_to_delete: list[dict] = []
        
        for link in links:
            uri = link.get("uri", "")
            if not uri:
                continue
            
            uri_lower = uri.lower()
            
            # Check against our known identity domains
            should_delete = any(domain in uri_lower for domain in IDENTITY_LINK_DOMAINS)
            
            # Also delete ANY external http(s) link — personal websites, portfolio, etc.
            if uri_lower.startswith("http://") or uri_lower.startswith("https://") or uri_lower.startswith("mailto:"):
                should_delete = True
            
            if should_delete:
                links_to_delete.append(link)
        
        # Delete collected links and redact their visual rectangles
        # 🎓 We iterate in REVERSE order because deleting a link can shift
        # internal indices. Reverse order keeps earlier indices valid.
        for link in reversed(links_to_delete):
            try:
                # Redact the visual area where the link text was displayed
                page.add_redact_annot(link["from"], fill=settings.REDACTION_FILL_COLOR)
                # Sever the digital hyperlink connection
                page.delete_link(link)
            except Exception as e:
                logger.warning(f"Failed to delete link on page {page_number}: {e}")
        
        # Step 3: Apply ALL redactions in one pass (text + link areas)
        if target_list or links_to_delete:
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)

    # Step 4: Scrub Document Metadata
    # 🎓 PDF files have hidden properties like "Author: John Doe" that most people
    # never see but are trivially accessible. We wipe everything.
    doc.set_metadata({})
    doc.del_xml_metadata()

    # Step 5: Serialize to memory bytes
    buf = io.BytesIO()
    
    # Save with aggressive cleanup:
    # garbage=4   : Removes ALL unreferenced objects (orphaned text fragments)
    # deflate=True: Compresses output (smaller file)
    # clean=True  : Sanitizes instruction streams
    doc.save(buf, garbage=4, deflate=True, clean=True)
    
    sanitized_bytes = buf.getvalue()
    buf.close()
    doc.close()

    return sanitized_bytes
