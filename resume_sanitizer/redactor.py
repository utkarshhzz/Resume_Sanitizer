from __future__ import annotations

import io
import logging
from collections import defaultdict

import fitz  # PyMuPDF

from resume_sanitizer.config import settings
from resume_sanitizer.models import PIIEntity, PageTextBlock, RedactionTarget
from resume_sanitizer.utils import expand_rect, merge_overlapping_rects, normalize_text_for_search

logger = logging.getLogger(__name__)

def build_redaction_targets(
    doc: fitz.Document, 
    entities: list[PIIEntity], 
    blocks: list[PageTextBlock], 
    ocr_used: bool
) -> list[RedactionTarget]:
    """
    Translates textual PII entities into physical geometric rectangles (bounding boxes)
    that we need to redact on the PDF pages.
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
            # Native PDFs have a text layer. We can tell PyMuPDF to explicitly search for the text string.
            search_text = normalize_text_for_search(entity.text)
            
            # quads=True returns a quadrilateral (4-point polygon) encompassing the text precisely
            quads = page.search_for(search_text, quads=True)
            
            # Fallback: Sometimes long entities get wrapped tightly spanning multiple lines causing failure. 
            # We search the first 15 chars as a fuzzy fallback.
            if len(quads) == 0 and len(search_text) > 15:
                quads = page.search_for(search_text[:15], quads=True)

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
            # OCR PDFs have an invisible text layer. But Tesseract gave us bounding boxes for individual words!
            page_block = block_map.get(entity.page)
            if page_block:
                # We iteratively find each word's offset in the full text string.
                # If a word's offset overlaps with our entity's [start, end] window, it's a match!
                current_offset = 0
                for w in page_block.words:
                    word_start = page_block.text.find(w.text, current_offset)
                    if word_start == -1:
                        continue
                    
                    word_end = word_start + len(w.text)
                    current_offset = word_end # advance the pointer
                    
                    # Check for overlap: does the word intersect the PII entity text?
                    if max(word_start, entity.start) < min(word_end, entity.end):
                        expanded = expand_rect(
                            (w.x0, w.y0, w.x1, w.y1),
                            settings.REDACTION_PADDING_PX,
                            page_rect.width,
                            page_rect.height
                        )
                        rects.append(expanded)

        # Optimization: Merge neighboring rectangles so it looks like one solid black bar 
        # instead of a fragmented dashed line over an email address.
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
    Applies the redactions permanently to the PDF.
    This does NOT just draw a black box on top. It deletes the physical text pathways 
    from the PDF binary structure.
    """
    # Group targets by page to process page-by-page efficiently
    page_targets = defaultdict(list)
    for t in targets:
        page_targets[t.page_number].append(t)

    for page_number, target_list in page_targets.items():
        page = doc[page_number - 1]
        
        # Step 1: Draw the Redaction Annotations
        for target in target_list:
            for rect_coords in target.rects:
                # fitz.Rect expects (x0, y0, x1, y1)
                rect_obj = fitz.Rect(*rect_coords)
                # Adds a special PDF instruction: "This area is marked for death"
                page.add_redact_annot(rect_obj, fill=settings.REDACTION_FILL_COLOR)

        # Step 2: Execute Redactions
        # PDF_REDACT_IMAGE_NONE ensures that we don't accidentally black out the background 
        # document image if this was a scanned resume! We only destroy the TEXT in that area.
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)
        
        # Step 2.5: Purge Clickable Hyperlinks (e.g. LinkedIn, GitHub)
        # Even if visual text is destroyed, the <a> tag link rectangle might survive!
        for link in page.get_links():
            uri = link.get("uri", "").lower()
            if any(domain in uri for domain in ["linkedin.com", "github.com", "wa.me", "mailto:", "facebook.com", "twitter.com", "portfolio", "bit.ly"]):
                # Add a redaction to that exact link box to erase any underlying text
                page.add_redact_annot(link["from"], fill=settings.REDACTION_FILL_COLOR)
                # Sever the digital hyperlink connection
                page.delete_link(link)
                
        # Must apply redactions AGAIN just in case the link loop caught something new
        page.apply_redactions(images=fitz.PDF_REDACT_IMAGE_NONE)

    # Step 3: Scrub Document Metadata (Crucial for Security!)
    # Sometimes resumes have "Author: John Doe" in the hidden file properties.
    doc.set_metadata({})
    doc.del_xml_metadata()

    # Step 4: Serialize to memory bytes securely
    buf = io.BytesIO()
    
    # Save parameters:
    # garbage=4   : Aggressive compression, deletes unused object paths.
    # deflate=True: Zip compression.
    # clean=True  : Sanitizes instruction streams.
    doc.save(buf, garbage=4, deflate=True, clean=True)
    
    sanitized_bytes = buf.getvalue()
    buf.close()
    doc.close()

    return sanitized_bytes
