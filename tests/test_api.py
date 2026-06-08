import pytest
import io

@pytest.mark.asyncio
async def test_health_endpoint(async_client):
    response = await async_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"

@pytest.mark.asyncio
async def test_sanitize_endpoint_200(async_client, sample_digital_pdf_bytes):
    # httpx expects files as a dictionary or a specific tuple format
    files = {"file": ("test.pdf", sample_digital_pdf_bytes, "application/pdf")}
    
    response = await async_client.post("/api/v1/sanitize?return_metadata=true", files=files)
    
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    
    # Check that custom headers were injected
    assert "x-request-id" in response.headers
    assert "x-pii-count" in response.headers
    assert int(response.headers["x-pii-count"]) > 0

@pytest.mark.asyncio
async def test_sanitize_rejects_non_pdf(async_client):
    files = {"file": ("test.txt", b"Hello world", "text/plain")}
    response = await async_client.post("/api/v1/sanitize", files=files)
    
    assert response.status_code == 415
    assert response.json()["error"] == "InvalidFileTypeError"

@pytest.mark.asyncio
async def test_analyze_only_returns_entities_json(async_client, sample_digital_pdf_bytes):
    files = {"file": ("test.pdf", sample_digital_pdf_bytes, "application/pdf")}
    response = await async_client.post("/api/v1/analyze-only", files=files)
    
    assert response.status_code == 200
    data = response.json()
    
    assert "entities" in data
    assert len(data["entities"]) > 0
    # Must contain our hardcoded email
    types = [e["entity_type"] for e in data["entities"]]
    assert "EMAIL_ADDRESS" in types

@pytest.mark.asyncio
async def test_cache_hit_on_second_request(async_client, sample_digital_pdf_bytes):
    # First request
    files1 = {"file": ("test.pdf", sample_digital_pdf_bytes, "application/pdf")}
    r1 = await async_client.post("/api/v1/sanitize", files=files1)
    assert r1.headers.get("x-cache") == "MISS"
    
    # Second request (identical bytes)
    files2 = {"file": ("test.pdf", sample_digital_pdf_bytes, "application/pdf")}
    r2 = await async_client.post("/api/v1/sanitize", files=files2)
    assert r2.headers.get("x-cache") == "HIT"
