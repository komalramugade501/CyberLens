# CyberLens — Suspicious Login Activity Detector

A runnable Flask demonstration project with registration, login, login-event auditing, risk flags, simulation controls, dashboard metrics, and CSV export.

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows PowerShell
```powershell
py -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
Copy-Item .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
```
Copy the generated value into `.env` as `SECRET_KEY=...`, then:
```powershell
python app.py
```
Open http://127.0.0.1:5000

## Features
- Password hashing using Werkzeug
- User registration and login sessions
- Login activity history (timestamp, IP, device, browser, location)
- Risk flags for repeated failures, new locations, and unusual hours
- Demo simulation buttons for suspicious patterns
- Dashboard summary and CSV export
- SQLite database created automatically

## Important limitations
This is an academic demo, not a production security monitoring platform. IP geolocation is not performed; location values are demo inputs. The simulation endpoints create synthetic events. Add CSRF protection, rate limiting, secure cookie settings, robust audit logging, and production secrets before deployment. Do not use the development secret key in production.
