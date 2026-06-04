from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from resume_sanitizer.config import settings

logger = logging.getLogger("middleware")

class RequestIDMiddleware(BaseHTTPMiddleware):
    """
    Injects a unique request ID (UUID) into every API call.
    This helps us track an individual user's request through logs.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate a unique tracker ID
        request_id = str(uuid.uuid4())
        
        # Save it into the FastAPI state for this request so other components can access it
        request.state.request_id = request_id
        
        # Proceed with the next step in the app
        response = await call_next(request)
        
        # Slap it onto the outgoing HTTP header so the client knows it too
        response.headers["X-Request-ID"] = request_id
        return response


class LoggingMiddleware(BaseHTTPMiddleware):
    """
    Logs the exact millisecond a request starts and stops, outputting structured JSON.
    Relies on RequestIDMiddleware running BEFORE it to use the injected UUID.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        req_id = getattr(request.state, "request_id", "unknown")
        
        logger.info({
            "event": "request",
            "method": request.method,
            "path": request.url.path,
            "request_id": req_id
        })
        
        start_time = time.perf_counter()
        
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            
            logger.info({
                "event": "response",
                "status": response.status_code,
                "duration_ms": round(duration_ms, 2),
                "request_id": req_id
            })
            return response
            
        except Exception as e:
            # If the app crashes horribly, we still want to log how long it took to die
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error({
                "event": "response_error",
                "status": 500,
                "duration_ms": round(duration_ms, 2),
                "request_id": req_id,
                "error": str(e)
            })
            raise


class FileSizeMiddleware(BaseHTTPMiddleware):
    """
    A bouncer that intercepts files that are too huge before they even enter the Python logic.
    """
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        
        # We only really care about blocking giant POST requests (like uploads)
        if request.method == "POST":
            content_length_str = request.headers.get("content-length")
            if content_length_str:
                content_length = int(content_length_str)
                max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
                if content_length > max_bytes:
                    return JSONResponse(
                        status_code=413, # 413 Payload Too Large
                        content={"error": "FileTooLarge", "message": f"File exceeds the maximum limit of {settings.MAX_UPLOAD_SIZE_MB}MB."}
                    )
                    
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    In-memory Sliding Window Rate Limiter.
    Prevents one bad actor from crashing the server by submitting 5000 resumes per second.
    NOTE: In a true multi-server production environment, this should be moved to Redis.
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)
        self.ip_window: dict[str, list[float]] = {}
        self.lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        
        # Lock ensures thread-safety if many requests hit the exact same millisecond
        async with self.lock:
            # Retrieve the list of recent timestamps for this IP
            timestamps = self.ip_window.get(client_ip, [])
            
            # Prune out the old timestamps that fall outside our "window"
            window_start = now - settings.RATE_LIMIT_WINDOW_SECONDS
            timestamps = [ts for ts in timestamps if ts > window_start]
            
            if len(timestamps) >= settings.RATE_LIMIT_REQUESTS:
                # Bouncer says No!
                return JSONResponse(
                    status_code=429, # 429 Too Many Requests
                    content={"error": "RateLimitExceeded", "message": "Too many requests. Please slow down."},
                    headers={"Retry-After": str(settings.RATE_LIMIT_WINDOW_SECONDS)}
                )

            # Record this valid request
            timestamps.append(now)
            self.ip_window[client_ip] = timestamps

        return await call_next(request)
