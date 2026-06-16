@echo off
cd /d "%~dp0"
if not exist "venv\Scripts\python.exe" (
    echo venv not found. Run: python -m venv venv ^& venv\Scripts\pip install -r requirements.txt
    exit /b 1
)
echo Starting Resume Sanitizer on http://localhost:8000
venv\Scripts\python.exe -m uvicorn resume_sanitizer.main:app --host 0.0.0.0 --port 8000 --reload
