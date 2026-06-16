# Start Resume Sanitizer API using the project venv (no re-download of deps).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$Python = Join-Path $Root "venv\Scripts\python.exe"

if (-not (Test-Path $Python)) {
    Write-Error "venv not found. Create it first: python -m venv venv; .\venv\Scripts\pip install -r requirements.txt"
}

Set-Location $Root
Write-Host "Starting Resume Sanitizer on http://localhost:8000 (Swagger: http://localhost:8000/docs)" -ForegroundColor Green
& $Python -m uvicorn resume_sanitizer.main:app --host 0.0.0.0 --port 8000 --reload
