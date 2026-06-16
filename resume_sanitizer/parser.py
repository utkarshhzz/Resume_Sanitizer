from __future__ import annotations

import io
import logging
from typing import Optional

import fitz  # PyMuPDF
from pdf2image import convert_from_bytes
import pytesseract
from pytesseract import Output
from PIL import Image

from resume_sanitizer.config import settings
from resume_sanitizer.exceptions import PDFCorruptedError, OCREngineError
from resume_sanitizer.models import PageTextBlock, WordBlock

logger = logging.getLogger(__name__)

def extract_text_digital(pdf_bytes: bytes) -> tuple[fitz.Document, list[PageTextBlock]]:
    """
    Extract text directly from the digital text layer of the PDF.
    This is extremely fast and accurate, but fails on scanned images.
    """
    try:
        # Open PDF from memory buffer entirely
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        # PyMuPDF raises different exceptions across versions:
        #   - fitz.FileDataError (older versions)
        #   - pymupdf.mupdf.FzErrorFormat (1.24+)
        # We catch broadly and wrap in our custom exception.
        raise PDFCorruptedError(f"Failed to open PDF: {e}")

    blocks: list[PageTextBlock] = []

    for page_num, page in enumerate(doc, start=1):
        # 1. Get raw word blocks: (x0, y0, x1, y1, word, block_no, line_no, word_no)
        raw_words = page.get_text("words")
        
        # 2. To get font sizes, we need the "dict" out. This is heavier, so we map it.
        # This will be useful later for our 'largest font = Name' heuristic.
        text_dict = page.get_text("dict")
        
        # Build a rough mapping of y-coordinate to font size to avoid a horrible O(N^2) loop
        font_size_map: dict[int, float] = {}
        for block in text_dict.get("blocks", []):
            if "lines" in block:
                for line in block["lines"]:
                    for span in line["spans"]:
                        # use approximate integer Y coord to map word to span
                        y_key = int(span["bbox"][1]) 
                        font_size_map[y_key] = span["size"]

        page_words: list[WordBlock] = []
        page_text_parts: list[str] = []

        last_block_no = -1
        last_line_no = -1

        for w in raw_words:
            x0, y0, x1, y1, word, block_no, line_no, word_no = w
            
            # Reconstruct whitespace (PyMuPDF strips spaces between words)
            if block_no != last_block_no and last_block_no != -1:
                page_text_parts.append("\n\n")  # New block / paragraph
            elif line_no != last_line_no and last_line_no != -1:
                page_text_parts.append("\n")    # New line
            elif page_words:
                page_text_parts.append(" ")     # Next word on same line
                
            last_block_no = block_no
            last_line_no = line_no
            
            page_text_parts.append(word)

            matched_font_size = font_size_map.get(int(y0), 11.0) # Default to 11.0 if not found

            page_words.append(
                WordBlock(
                    text=word,
                    x0=x0,
                    y0=y0,
                    x1=x1,
                    y1=y1,
                    page_number=page_num,
                    confidence=-1,  # Digital path has 100% confidence, using -1 as placeholder
                    font_size=matched_font_size,
                    is_bold=False # Simplified for now
                )
            )

        blocks.append(
            PageTextBlock(
                page_number=page_num,
                text="".join(page_text_parts),
                words=page_words
            )
        )

    return doc, blocks

def needs_ocr(blocks: list[PageTextBlock]) -> bool:
    """
    Check if the PDF is essentially an image.
    If total characters across all pages is tiny, it's definitely a scanned photo.
    """
    total_chars = sum(len(b.text.strip()) for b in blocks)
    return total_chars < settings.OCR_CHAR_THRESHOLD

def extract_text_ocr(pdf_bytes: bytes) -> list[PageTextBlock]:
    """
    Fallback method: Convert PDF to images -> run Tesseract OCR -> map coords back to PDF space.
    """
    logger.info("Triggering OCR fallback extraction.")
    try:
        images = convert_from_bytes(pdf_bytes, dpi=settings.OCR_DPI)
    except Exception as e:
        raise OCREngineError(f"Failed to convert PDF to images: {e}")

    blocks: list[PageTextBlock] = []
    
    # PDF point space is inherently 72 DPI. We must scale down our image pixels.
    scale_factor = 72.0 / settings.OCR_DPI

    for page_num, img in enumerate(images, start=1):
        # Run Tesseract to get bounding boxes and confidences dict
        try:
            ocr_data = pytesseract.image_to_data(img, output_type=Output.DICT, lang=settings.OCR_LANGUAGE)
        except Exception as e:
            raise OCREngineError(f"Tesseract OCR failed: {e}")
            
        page_words: list[WordBlock] = []
        page_text_parts: list[str] = []
        
        last_block_num = -1
        last_line_num = -1

        for i in range(len(ocr_data['text'])):
            word = ocr_data['text'][i]
            conf = int(ocr_data['conf'][i])
            
            # Skip empty strings and low confidence gibberish
            if not word.strip() or conf < settings.OCR_CONFIDENCE_THRESHOLD:
                continue

            block_num = ocr_data['block_num'][i]
            line_num = ocr_data['line_num'][i]

            # Reconstruct whitespace
            if block_num != last_block_num and last_block_num != -1:
                page_text_parts.append("\n\n")
            elif line_num != last_line_num and last_line_num != -1:
                page_text_parts.append("\n")
            elif page_words:
                page_text_parts.append(" ")

            last_block_num = block_num
            last_line_num = line_num
            
            page_text_parts.append(word)

            # Tesseract gives X, Y, Width, Height in pixels. Convert to PDF points coordinates.
            px_x0 = ocr_data['left'][i]
            px_y0 = ocr_data['top'][i]
            px_x1 = px_x0 + ocr_data['width'][i]
            px_y1 = px_y0 + ocr_data['height'][i]

            page_words.append(
                WordBlock(
                    text=word,
                    x0=px_x0 * scale_factor,
                    y0=px_y0 * scale_factor,
                    x1=px_x1 * scale_factor,
                    y1=px_y1 * scale_factor,
                    page_number=page_num,
                    confidence=conf,
                    font_size=-1.0, # Not practically available in OCR
                    is_bold=False
                )
            )
            
        blocks.append(
            PageTextBlock(
                page_number=page_num,
                text="".join(page_text_parts),
                words=page_words
            )
        )

    return blocks

def extract(pdf_bytes: bytes) -> tuple[fitz.Document | None, list[PageTextBlock], bool]:
    """
    Orchestrator: Tries digital extraction first. If it looks like a scanned document,
    it falls back to a full OCR scan.
    """
    doc, blocks = extract_text_digital(pdf_bytes)
    ocr_used = False

    if needs_ocr(blocks):
        ocr_blocks = extract_text_ocr(pdf_bytes)
        # Even if we use OCR, we MUST keep the original `doc` object open 
        # so the redactor can draw black boxes onto it later!
        return doc, ocr_blocks, True

    return doc, blocks, ocr_used
