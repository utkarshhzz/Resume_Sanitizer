from __future__ import annotations

class SanitizerBaseError(Exception):
    """
    The base exception class for our application. 
    All other custom exceptions will inherit from this one.
    This makes it easy to catch any 'expected' error in one place.
    """
    def __init__(self, message: str, detail: str | None = None, status_code: int = 500):
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.status_code = status_code

class FileTooLargeError(SanitizerBaseError):
    def __init__(self, message: str = "File exceeds maximum allowed size.", detail: str | None = None):
        super().__init__(message, detail, 413) # Payload Too Large

class InvalidFileTypeError(SanitizerBaseError):
    def __init__(self, message: str = "Invalid file type. Only PDF is supported.", detail: str | None = None):
        super().__init__(message, detail, 415) # Unsupported Media Type

class PDFCorruptedError(SanitizerBaseError):
    def __init__(self, message: str = "The PDF file is corrupted or unreadable.", detail: str | None = None):
        super().__init__(message, detail, 422) # Unprocessable Entity

class OCREngineError(SanitizerBaseError):
    def __init__(self, message: str = "An error occurred during OCR processing.", detail: str | None = None):
        super().__init__(message, detail, 500) # Internal Server Error

class PIIAnalysisError(SanitizerBaseError):
    def __init__(self, message: str = "An error occurred during PII detection.", detail: str | None = None):
        super().__init__(message, detail, 500)

class RedactionError(SanitizerBaseError):
    def __init__(self, message: str = "An error occurred while redacting the PDF.", detail: str | None = None):
        super().__init__(message, detail, 500)

class CacheError(SanitizerBaseError):
    def __init__(self, message: str = "An error occurred interacting with the cache.", detail: str | None = None):
        super().__init__(message, detail, 500)
