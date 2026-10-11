"""Passive HTTP security-header auditor for educational use."""

from __future__ import annotations

import html
import ipaddress
import re
import socket
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests
from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

REQUEST_TIMEOUT = (4, 10)
MAX_REDIRECTS = 5
USER_AGENT = "EducationalSecurityHeaderAuditor/1.0"

# Missing-header deductions total 100 points. Weak values incur 60% of that
# header's missing penalty, rounded up, so a present-but-unsafe value matters.
HEADER_DEFINITIONS = [
    {
        "name": "Strict-Transport-Security",
        "purpose": "Tells browsers to use HTTPS for future visits.",
        "recommendation": "Serve the site over HTTPS and set a suitable max-age (at least 15552000 seconds); consider includeSubDomains after checking every subdomain.",
        "missing_deduction": 20,
        "weak_reason": "The max-age is missing, invalid, zero, or shorter than 180 days.",
    },
    {
        "name": "Content-Security-Policy",
        "purpose": "Restricts where scripts and other page resources may load from, reducing some injection risks.",
        "recommendation": "Define a restrictive policy, including default-src and carefully chosen script-src sources; avoid wildcards and unsafe-inline/unsafe-eval where possible.",
        "missing_deduction": 25,
        "weak_reason": "The policy is empty, lacks default-src, or contains broad wildcard/unsafe script sources.",
    },
    {
        "name": "X-Content-Type-Options",
        "purpose": "Prevents browsers from guessing a different content type (MIME sniffing).",
        "recommendation": "Set X-Content-Type-Options: nosniff.",
        "missing_deduction": 15,
        "weak_reason": "The value is not nosniff.",
    },
    {
        "name": "X-Frame-Options",
        "purpose": "Helps prevent other sites from embedding pages in frames for clickjacking.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN; a CSP frame-ancestors directive is the modern complementary control.",
        "missing_deduction": 15,
        "weak_reason": "The value is not DENY or SAMEORIGIN.",
    },
    {
        "name": "Referrer-Policy",
        "purpose": "Controls how much URL information is sent as a referrer to other sites.",
        "recommendation": "Use strict-origin-when-cross-origin or a more restrictive policy such as no-referrer.",
        "missing_deduction": 10,
        "weak_reason": "The policy is empty, unrecognized, or permits the full URL to be sent with unsafe-url.",
    },
    {
        "name": "Permissions-Policy",
        "purpose": "Limits browser features such as camera, microphone, and geolocation.",
        "recommendation": "Explicitly disable unused features or restrict them to trusted origins; avoid wildcard allowlists.",
        "missing_deduction": 15,
        "weak_reason": "The policy is empty or contains a wildcard allowlist.",
    },
]

REFERRER_POLICIES = {
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url",
}


class ScanError(Exception):
    """An expected, user-safe scan failure."""


def _is_public_ip(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return parsed.is_global


def validate_url(raw_url: str) -> str:
    """Validate a URL and reject hostnames resolving to non-public IPs."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ScanError("Enter a website URL to analyze.")
    raw_url = raw_url.strip()
    if len(raw_url) > 2048:
        raise ScanError("The URL is too long.")

    try:
        parts = urlsplit(raw_url)
        hostname = parts.hostname
        port = parts.port
    except ValueError:
        raise ScanError("Enter a valid HTTP or HTTPS URL.") from None

    if parts.scheme.lower() not in {"http", "https"} or not hostname:
        raise ScanError("Enter a complete URL beginning with http:// or https://.")
    if parts.username is not None or parts.password is not None:
        raise ScanError("URLs containing usernames or passwords are not allowed.")

    hostname = hostname.rstrip(".").lower()
    if not hostname or hostname == "localhost" or hostname.endswith((".localhost", ".local", ".internal")):
        raise ScanError("This tool only accepts publicly reachable website addresses.")

    try:
        ipaddress.ip_address(hostname)
        addresses = [hostname]
    except ValueError:
        try:
            records = socket.getaddrinfo(
                hostname,
                port or (443 if parts.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
        except (socket.gaierror, UnicodeError, OSError):
            raise ScanError("The website hostname could not be resolved.") from None
        addresses = list({record[4][0] for record in records})

    if not addresses:
        raise ScanError("The website hostname did not resolve to an address.")
    if any(not _is_public_ip(address) for address in addresses):
        raise ScanError("This tool only accepts destinations that resolve exclusively to public IP addresses.")

    return urlunsplit((parts.scheme.lower(), parts.netloc, parts.path or "/", parts.query, ""))


def _weak_header_reason(name: str, value: str) -> str | None:
    normalized = value.strip().lower()
    if name == "Strict-Transport-Security":
        match = re.search(r"(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)", normalized)
        if not match or int(match.group(1)) < 15_552_000:
            return HEADER_DEFINITIONS[0]["weak_reason"]
    elif name == "Content-Security-Policy":
        directives = [part.strip() for part in normalized.split(";") if part.strip()]
        tokens = [directive.split() for directive in directives]
        if not directives or not any(parts[0] == "default-src" for parts in tokens):
            return HEADER_DEFINITIONS[1]["weak_reason"]
        risky_sources = {"*", "http:", "https:", "data:", "'unsafe-inline'", "'unsafe-eval'"}
        if any(source in risky_sources for parts in tokens for source in parts[1:]):
            return HEADER_DEFINITIONS[1]["weak_reason"]
    elif name == "X-Content-Type-Options" and normalized != "nosniff":
        return HEADER_DEFINITIONS[2]["weak_reason"]
    elif name == "X-Frame-Options" and normalized not in {"deny", "sameorigin"}:
        return HEADER_DEFINITIONS[3]["weak_reason"]
    elif name == "Referrer-Policy":
        policy = normalized.split(",", 1)[0].strip()
        if policy not in REFERRER_POLICIES or policy == "unsafe-url":
            return HEADER_DEFINITIONS[4]["weak_reason"]
    elif name == "Permissions-Policy" and (not normalized or re.search(r"=\s*(?:\*|\(\s*\*\s*\))", normalized)):
        return HEADER_DEFINITIONS[5]["weak_reason"]
    return None


def calculate_score(findings: list[dict]) -> tuple[int, str]:
    """Apply documented deductions and return a bounded score and status."""
    deduction = sum(item["points_deducted"] for item in findings)
    score = max(0, min(100, 100 - deduction))
    if score >= 80:
        status = "Good"
    elif score >= 50:
        status = "Needs Improvement"
    else:
        status = "Poor"
    return score, status


def _build_findings(response_headers) -> tuple[list[dict], int, str]:
    findings = []
    for definition in HEADER_DEFINITIONS:
        name = definition["name"]
        value = response_headers.get(name)
        if value is None or not str(value).strip():
            status = "Missing"
            risk = f"{name} is not set, so this browser protection may not be active."
            points = definition["missing_deduction"]
        else:
            value = str(value).strip()
            weak_reason = _weak_header_reason(name, value)
            if weak_reason:
                status = "Weak"
                risk = weak_reason
                points = (definition["missing_deduction"] * 3 + 4) // 5
            else:
                status = "Present"
                risk = "No obvious weakness was identified by this basic check."
                points = 0
        findings.append(
            {
                "name": name,
                "status": status,
                "value": value or "",
                "purpose": definition["purpose"],
                "recommendation": definition["recommendation"],
                "risk": risk,
                "points_deducted": points,
            }
        )
    score, assessment = calculate_score(findings)
    return findings, score, assessment


def analyze_target(raw_url: str) -> dict:
    """Fetch response headers only, validating every redirect destination."""
    current_url = raw_url
    response = None
    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            current_url = validate_url(current_url)
            response = requests.get(
                current_url,
                headers={"User-Agent": USER_AGENT},
                timeout=REQUEST_TIMEOUT,
                allow_redirects=False,
                stream=True,
            )
            if response.status_code not in {301, 302, 303, 307, 308}:
                break
            location = response.headers.get("Location")
            response.close()
            response = None
            if not location:
                break
            if redirect_count >= MAX_REDIRECTS:
                raise ScanError("The website redirected too many times.")
            current_url = urljoin(current_url, location)

        if response is None:
            raise ScanError("The website returned a redirect without a usable response.")

        findings, score, assessment = _build_findings(response.headers)
        notices = []
        if response.status_code >= 400:
            notices.append(f"The website returned HTTP {response.status_code}; its response headers are still shown.")
        if all(item["status"] == "Missing" for item in findings):
            notices.append("The response did not include any of the six security headers checked.")
        return {
            "ok": True,
            "target_url": raw_url,
            "final_url": current_url,
            "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "http_status": response.status_code,
            "score": score,
            "assessment": assessment,
            "headers_checked": len(findings),
            "present_count": sum(item["status"] == "Present" for item in findings),
            "weak_count": sum(item["status"] == "Weak" for item in findings),
            "missing_count": sum(item["status"] == "Missing" for item in findings),
            "findings": findings,
            "notice": " ".join(notices),
            "disclaimer": "Educational assessment of HTTP response headers only; it is not a complete website security rating.",
        }
    except ScanError:
        raise
    except requests.Timeout:
        raise ScanError("The website request timed out. Try again later.") from None
    except requests.RequestException:
        raise ScanError("The website could not be reached. Check the address and try again.") from None
    finally:
        if response is not None:
            response.close()


def create_html_report(result: dict) -> str:
    """Render a standalone report while escaping all dynamic text."""
    esc = lambda value: html.escape(str(value), quote=True)
    rows = []
    for finding in result.get("findings", []):
        rows.append(
            "<tr>"
            f"<td>{esc(finding.get('name', ''))}</td>"
            f"<td>{esc(finding.get('status', ''))}</td>"
            f"<td><code>{esc(finding.get('value') or 'Not set')}</code></td>"
            f"<td>{esc(finding.get('purpose', ''))}</td>"
            f"<td>{esc(finding.get('risk', ''))}</td>"
            f"<td>{esc(finding.get('recommendation', ''))}</td>"
            "</tr>"
        )
    document = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Header Audit Report</title><style>
body{font:16px/1.5 Segoe UI,Arial,sans-serif;margin:2rem auto;padding:0 1rem;max-width:1100px;color:#202724}
h1{color:#143c35}table{border-collapse:collapse;width:100%;margin:1.5rem 0}th,td{border:1px solid #ccd5d0;padding:.65rem;text-align:left;vertical-align:top}th{background:#e7efeb}
code{overflow-wrap:anywhere}.score{font-size:1.4rem;font-weight:700}.disclaimer{border-left:4px solid #d38743;padding:.75rem;background:#fff5e9}
</style></head><body><h1>Automated Web Application Security Header Analysis Tool</h1>
<p><strong>Target:</strong> """ + esc(result.get("target_url", "")) + """</p>
<p><strong>Scanned:</strong> """ + esc(result.get("scanned_at", "")) + """</p>
<p><strong>HTTP status:</strong> """ + esc(result.get("http_status", "")) + """</p>
<p class="score">Security score: """ + esc(result.get("score", "")) + "/100 | " + esc(result.get("assessment", "")) + """</p>
<table><thead><tr><th>Header</th><th>Status</th><th>Value</th><th>Purpose</th><th>Risk</th><th>Recommendation</th></tr></thead><tbody>"""
    return "".join(
        [
            document,
            "".join(rows),
            "</tbody></table><p class=\"disclaimer\">",
            esc(result.get("disclaimer", "Results cover HTTP security headers only; this is not a complete security assessment.")),
            "</p></body></html>",
        ]
    )


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    payload = request.get_json(silent=True) or {}
    try:
        result = analyze_target(payload.get("url", ""))
        return jsonify(result)
    except ScanError as error:
        return jsonify({"ok": False, "error": str(error)}), 400


@app.post("/report")
def download_report():
    payload = request.get_json(silent=True) or {}
    result = payload.get("result")
    if not isinstance(result, dict) or not isinstance(result.get("findings"), list):
        return jsonify({"error": "A completed scan report is required."}), 400
    report = create_html_report(result)
    return Response(
        report,
        mimetype="text/html",
        headers={"Content-Disposition": 'attachment; filename="security-header-report.html"'},
    )


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify({"error": "The request is too large."}), 413


@app.errorhandler(500)
def internal_error(_error):
    return jsonify({"error": "The scan could not be completed due to an internal error."}), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)