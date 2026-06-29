from __future__ import annotations

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
    """Extract text from the digital text layer of a PDF."""
    try:
        doc = fitz.open(stream=pdf_bytes, filetype="pdf")
    except Exception as e:
        raise PDFCorruptedError(f"Failed to open PDF: {e}")

    blocks: list[PageTextBlock] = []

    for page_num, page in enumerate(doc, start=1):
        raw_words = page.get_text("words")
        text_dict = page.get_text("dict")

        # Map y-coordinate to font size for the largest-font-name heuristic
        font_size_map: dict[int, float] = {}
        for block in text_dict.get("blocks", []):
            if "lines" in block:
                for line in block["lines"]:
                    for span in line["spans"]:
                        font_size_map[int(span["bbox"][1])] = span["size"]

        page_words: list[WordBlock] = []
        page_text_parts: list[str] = []
        last_block_no = -1
        last_line_no = -1

        for w in raw_words:
            x0, y0, x1, y1, word, block_no, line_no, word_no = w

            # Reconstruct whitespace between words
            if block_no != last_block_no and last_block_no != -1:
                page_text_parts.append("\n\n")
            elif line_no != last_line_no and last_line_no != -1:
                page_text_parts.append("\n")
            elif page_words:
                page_text_parts.append(" ")

            last_block_no = block_no
            last_line_no = line_no
            page_text_parts.append(word)

            page_words.append(WordBlock(
                text=word, x0=x0, y0=y0, x1=x1, y1=y1,
                page_number=page_num, confidence=-1,
                font_size=font_size_map.get(int(y0), 11.0),
                is_bold=False
            ))

        blocks.append(PageTextBlock(
            page_number=page_num,
            text="".join(page_text_parts),
            words=page_words
        ))

    return doc, blocks


def needs_ocr(blocks: list[PageTextBlock]) -> bool:
    """True if the PDF has too few chars (likely a scanned image)."""
    total_chars = sum(len(b.text.strip()) for b in blocks)
    return total_chars < settings.OCR_CHAR_THRESHOLD


def extract_text_ocr(pdf_bytes: bytes) -> list[PageTextBlock]:
    """Fallback: convert PDF pages to images and run Tesseract OCR."""
    logger.info("Triggering OCR fallback extraction.")
    try:
        images = convert_from_bytes(pdf_bytes, dpi=settings.OCR_DPI)
    except Exception as e:
        raise OCREngineError(f"Failed to convert PDF to images: {e}")

    blocks: list[PageTextBlock] = []
    scale_factor = 72.0 / settings.OCR_DPI  # Convert image pixels to PDF points

    for page_num, img in enumerate(images, start=1):
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

            if not word.strip() or conf < settings.OCR_CONFIDENCE_THRESHOLD:
                continue

            block_num = ocr_data['block_num'][i]
            line_num = ocr_data['line_num'][i]

            if block_num != last_block_num and last_block_num != -1:
                page_text_parts.append("\n\n")
            elif line_num != last_line_num and last_line_num != -1:
                page_text_parts.append("\n")
            elif page_words:
                page_text_parts.append(" ")

            last_block_num = block_num
            last_line_num = line_num
            page_text_parts.append(word)

            px_x0 = ocr_data['left'][i]
            px_y0 = ocr_data['top'][i]
            px_x1 = px_x0 + ocr_data['width'][i]
            px_y1 = px_y0 + ocr_data['height'][i]

            page_words.append(WordBlock(
                text=word,
                x0=px_x0 * scale_factor, y0=px_y0 * scale_factor,
                x1=px_x1 * scale_factor, y1=px_y1 * scale_factor,
                page_number=page_num, confidence=conf,
                font_size=-1.0, is_bold=False
            ))

        blocks.append(PageTextBlock(
            page_number=page_num,
            text="".join(page_text_parts),
            words=page_words
        ))

    return blocks


def extract(pdf_bytes: bytes) -> tuple[fitz.Document | None, list[PageTextBlock], bool]:
    """Orchestrator: try digital extraction first, fallback to OCR if needed."""
    doc, blocks = extract_text_digital(pdf_bytes)

    if needs_ocr(blocks):
        ocr_blocks = extract_text_ocr(pdf_bytes)
        return doc, ocr_blocks, True

    return doc, blocks, False
