# Automated Web Application Security Header Analysis Tool

A beginner-friendly Flask application that passively inspects six HTTP response security headers and presents a scored, downloadable report. It sends a normal HTTP GET request and does not run exploits, payloads, password attacks, or destructive checks.

## Features

- Responsive dashboard with score, assessment, header summary, risks, and recommendations.
- Checks HSTS, Content-Security-Policy, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
- Distinguishes missing, present, and obviously weak values rather than treating every present header as secure.
- Blocks local and non-public IP destinations, checks DNS results, and validates each redirect before following it.
- Uses bounded redirects and connection/read timeouts; scan data is not saved by the application.
- Downloads a standalone HTML report with escaped dynamic content.
- Offline unit tests use mocked DNS and HTTP responses.

## Requirements

- Windows 11 (also runs on other platforms)
- Python 3.10 or newer
- Internet access for scanning public websites; the dashboard and tests run locally

## Install and run on Windows

Open PowerShell in this project folder and run:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000) in your browser. If PowerShell blocks virtual-environment activation, use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window, then activate again.

Run the test suite from the project folder:

```powershell
python -m unittest discover -s tests -v
```

## Scoring

The backend starts at 100 points. Missing-header deductions are HSTS 20, CSP 25, X-Content-Type-Options 15, X-Frame-Options 15, Referrer-Policy 10, and Permissions-Policy 15. These sum to 100. A weak value receives 60% of that header's missing penalty, rounded up. The result is clamped to 0–100. Scores of 80–100 are Good, 50–79 Need Improvement, and 0–49 Poor. A strong-looking value only means this basic check found no obvious weakness; it is not proof that the configuration is safe.

## Limitations and ethical use

This is an educational HTTP-header check, not a penetration test or complete website security rating. It does not inspect application code, TLS configuration, cookies, page content, or whether a declared policy works as intended. Header syntax checks are intentionally basic. DNS is resolved and all returned addresses must be public before each request, but this application uses the standard Requests resolver for the actual connection, so DNS rebinding cannot be eliminated completely. Do not use this tool against a site unless you own it or have permission to assess it. Avoid scanning sensitive or high-traffic services; only a single lightweight GET is sent per redirect hop.

The development server binds to `127.0.0.1` and is not intended for production deployment. No submitted URL or result is written to a database or file by the application.