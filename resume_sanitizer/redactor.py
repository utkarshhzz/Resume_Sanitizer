from __future__ import annotations

import io
import logging
from collections import defaultdict

import fitz  # PyMuPDF

from resume_sanitizer.config import settings
from resume_sanitizer.models import PIIEntity, PageTextBlock, RedactionTarget
from resume_sanitizer.utils import expand_rect, merge_overlapping_rects, normalize_text_for_search

logger = logging.getLogger(__name__)

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
        # PyMuPDF pages are 0-indexed, but our models use 1-indexed page_numbers
        page_index = entity.page - 1
        
        # Guard against invalid pages
        if page_index < 0 or page_index >= doc.page_count:
            logger.warning(f"Entity page {entity.page} out of bounds.")
            continue
            
        page = doc[page_index]
        page_rect = page.rect
        rects: list[tuple[float, float, float, float]] = []

        if not ocr_used:
            # --- DIGITAL PATH ---
            # 🎓 Native PDFs have a hidden text layer. PyMuPDF can search this layer
            # for a string and return the EXACT pixel coordinates where it appears.
            search_text = normalize_text_for_search(entity.text)
            
            # quads=True returns a quadrilateral (4-point polygon) encompassing the text
            quads = page.search_for(search_text, quads=True)
            
            # Fallback: Sometimes long entities span lines and PyMuPDF can't find them.
            # We try progressively shorter prefixes.
            if len(quads) == 0 and len(search_text) > 15:
                quads = page.search_for(search_text[:15], quads=True)
            if len(quads) == 0 and len(search_text) > 8:
                quads = page.search_for(search_text[:8], quads=True)

            for q in quads:
                r = q.rect  # Convert Quad to Rect
                expanded = expand_rect(
                    (r.x0, r.y0, r.x1, r.y1),
                    settings.REDACTION_PADDING_PX,
                    page_rect.width,
                    page_rect.height
                )
                rects.append(expanded)
        else:
            # --- OCR PATH ---
            # 🎓 For scanned PDFs, Tesseract gave us bounding boxes for each word.
            # We map the entity's character offset to the matching word bboxes.
            page_block = block_map.get(entity.page)
            if page_block:
                current_offset = 0
                for w in page_block.words:
                    word_start = page_block.text.find(w.text, current_offset)
                    if word_start == -1:
                        continue
                    
                    word_end = word_start + len(w.text)
                    current_offset = word_end
                    
                    # Check for overlap: does the word intersect the PII entity text?
                    if max(word_start, entity.start) < min(word_end, entity.end):
                        expanded = expand_rect(
                            (w.x0, w.y0, w.x1, w.y1),
                            settings.REDACTION_PADDING_PX,
                            page_rect.width,
                            page_rect.height
                        )
                        rects.append(expanded)

        # Merge neighboring rectangles so multi-word entities get one clean block
        merged_rects = merge_overlapping_rects(rects)

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

        # Step 2: Execute Text Redactions
        # PDF_REDACT_IMAGE_NONE preserves embedded images while destroying text
        if target_list:
            page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
        
        # Step 3: Purge Clickable Hyperlinks
        # 🎓 Teacher Note: Even after we erase the VISIBLE text "linkedin.com/in/john",
        # the PDF might still contain an invisible CLICKABLE RECTANGLE that links to that URL.
        # A company receiving the resume could hover over the blank space and still find the link!
        # We must sever these digital hyperlinks too.
        #
        # BUG FIX: Previously we deleted links while iterating page.get_links().
        # This is the classic "modify list while iterating" bug — it skips items.
        # Fix: collect links to delete first, then delete in reverse order.
        
        links = page.get_links()
        links_to_delete: list[dict] = []
        
        for link in links:
            uri = link.get("uri", "")
            if not uri:
                continue
            
            uri_lower = uri.lower()
            
            # Check against our known identity domains
            should_delete = any(domain in uri_lower for domain in IDENTITY_LINK_DOMAINS)
            
            # Also delete ANY external http(s) link — personal websites, portfolio, etc.
            # 🎓 This is aggressive but correct for your use case:
            # On a resume, ALL hyperlinks are either personal (bad) or company URLs (harmless but rare).
            # Since you're a bridge service, removing all links is safer than missing one.
            if uri_lower.startswith("http://") or uri_lower.startswith("https://") or uri_lower.startswith("mailto:"):
                should_delete = True
            
            if should_delete:
                links_to_delete.append(link)
        
        # Delete collected links and redact their visual rectangles
        # 🎓 We iterate in REVERSE order because deleting a link changes the indices
        # of subsequent links in the internal PDF structure.
        for link in reversed(links_to_delete):
            # Redact the visual area where the link text was displayed
            page.add_redact_annot(link["from"], fill=settings.REDACTION_FILL_COLOR)
            # Sever the digital hyperlink connection
            page.delete_link(link)
        
        # Apply redactions again to clean up any link text we just marked
        if links_to_delete:
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
