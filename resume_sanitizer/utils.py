from __future__ import annotations

import hashlib
import re
import time
from typing import Callable, Any, Generator, Coroutine, TypeVar
from functools import wraps

T = TypeVar('T')

def compute_sha256(buffer: bytes) -> str:
    """Computes a SHA-256 hex digest of raw bytes."""
    return hashlib.sha256(buffer).hexdigest()

def timeit_async(func: Callable[..., Coroutine[Any, Any, T]]) -> Callable[..., Coroutine[Any, Any, tuple[T, float]]]:
    """
    Async decorator that records the execution time of a function.
    Returns a tuple containing the original returned result and the elapsed time in milliseconds.
    """
    @wraps(func)
    async def wrapper(*args, **kwargs) -> tuple[T, float]:
        start = time.perf_counter()
        result = await func(*args, **kwargs)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        return result, elapsed_ms
    return wrapper

def expand_rect(rect: tuple[float, float, float, float], padding: int, page_width: float, page_height: float) -> tuple[float, float, float, float]:
    """
    Expand a rectangle (x0, y0, x1, y1) by a specified padding in all directions.
    The resulting coordinates are clamped to the page boundaries so they don't go off-screen.
    """
    x0, y0, x1, y1 = rect
    return (
        max(0.0, x0 - padding),
        max(0.0, y0 - padding),
        min(page_width, x1 + padding),
        min(page_height, y1 + padding)
    )

def merge_overlapping_rects(rects: list[tuple[float, float, float, float]]) -> list[tuple[float, float, float, float]]:
    """
    Merge horizontally overlapping/adjacent redaction rectangles on the same line.
    This avoids having fragmented black boxes over multi-word entities (like a full name).
    Uses a sweep-line algorithm sorting by x0 first.
    """
    if not rects:
        return []
        
    # Sort boxes primarily by y0 (top to bottom), then by x0 (left to right)
    # Give a small tolerance to y0 (e.g. 5 pixels) since lines can be slightly crooked.
    sorted_rects = sorted(rects, key=lambda r: (round(r[1] / 5.0) * 5, r[0]))
    
    merged = [sorted_rects[0]]
    threshold = 8.0  # Number of pixels horizontally between words to consider "adjacent"

    for current in sorted_rects[1:]:
        last = merged[-1]
        
        # Unpack last and current
        lx0, ly0, lx1, ly1 = last
        cx0, cy0, cx1, cy1 = current

        # Check if they are roughly on the same line.
        y_overlap = max(0, min(ly1, cy1) - max(ly0, cy0))
        same_line = y_overlap > 0 or (abs(ly0 - cy0) <= 5.0)

        # Check if current starts close enough to where last ended
        if same_line and (cx0 <= lx1 + threshold):
            # Merge them: take the min bounds for top/left and max for bottom/right
            merged[-1] = (
                min(lx0, cx0),
                min(ly0, cy0),
                max(lx1, cx1),
                max(ly1, cy1)
            )
        else:
            merged.append(current)

    return merged

def normalize_text_for_search(text: str) -> str:
    """
    Normalize unicode and collapse whitespace for reliable PyMuPDF page.search_for() matching.
    """
    # Replace any sequence of whitespace characters (newlines, tabs, multiple spaces) with a single space.
    normalized = re.sub(r'\s+', ' ', text)
    return normalized.strip()

def chunk_list(lst: list[Any], size: int) -> Generator[list[Any], None, None]:
    """Yield successive chunks of specific size from a list."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]
