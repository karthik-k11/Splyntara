import json
import re
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import HTTPException

from config import Config
from database import init_app as init_database
from services.dependency_discovery import STATUS_ERROR, discover_dependencies
from services.risk_analyzer import STATUS_ERROR as RISK_STATUS_ERROR
from services.risk_analyzer import analyze_risks
from services.sbom_generator import STATUS_ERROR as SBOM_STATUS_ERROR
from services.sbom_generator import generate_sbom
from services.security_dashboard import (
    analyze_security_dashboard,
    build_dashboard_error,
)
from services.vulnerability_scanner import (
    STATUS_ERROR as VULNERABILITY_STATUS_ERROR,
    scan_vulnerabilities,
)

MAX_PROJECT_DIRECTORY_LENGTH = 8_192
API_PATH_PREFIXES = ("/api/", "/dependencies/", "/sbom/")
HTTP_ERROR_MESSAGES = {
    400: "bad request",
    404: "not found",
    405: "method not allowed",
    413: "request body is too large",
    415: "unsupported media type",
}


def create_app(config=None):
    app = Flask(__name__)

    app.config.from_object(Config)

    if config is not None:
        app.config.from_mapping(config)

    database_path = Path(app.config["DATABASE"])
    app.config["DATABASE"] = database_path
    database_path.parent.mkdir(parents=True, exist_ok=True)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        if not _is_api_request():
            return error

        message = HTTP_ERROR_MESSAGES.get(error.code, "request failed")
        return _plain_error_response(message), error.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_exception(error):
        app.logger.exception(
            "Unhandled exception while processing %s %s",
            request.method,
            request.path,
        )
        message = "internal server error"

        if _is_api_request():
            return _plain_error_response(message), 500

        return "Internal Server Error", 500

    @app.get("/health")
    def health():
        return jsonify({
            "status": "ok",
            "application": "Splyntara"
        }), 200

    @app.route("/api/dependencies/discover", methods=["GET", "POST"])
    def discover_dependencies_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return _error_response(error), 400

        result = discover_dependencies(project_directory)

        if result["status"] == STATUS_ERROR:
            message = result["warnings"][0] if result["warnings"] else "scan failed"
            return jsonify({**result, "error": message}), 400

        return jsonify(result), 200

    app.add_url_rule(
        "/dependencies/discover",
        endpoint="discover_dependencies_alias",
        view_func=discover_dependencies_endpoint,
        methods=["GET", "POST"],
    )

    @app.route("/api/sbom/generate", methods=["GET", "POST"])
    @app.route("/api/sbom", methods=["GET", "POST"])
    def generate_sbom_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return _sbom_error_response(error), 400

        result = generate_sbom(project_directory)

        if result["status"] == SBOM_STATUS_ERROR:
            return jsonify(result), 400

        return jsonify(result["sbom"]), 200

    app.add_url_rule(
        "/sbom/generate",
        endpoint="generate_sbom_alias",
        view_func=generate_sbom_endpoint,
        methods=["GET", "POST"],
    )

    @app.post("/api/vulnerabilities/scan")
    def scan_vulnerabilities_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return _vulnerability_error_response(error), 400

        result = scan_vulnerabilities(project_directory)

        if result["status"] == VULNERABILITY_STATUS_ERROR:
            return jsonify(result), 400

        return jsonify(result), 200

    @app.post("/api/risks/analyze")
    def analyze_risks_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return _risk_error_response(error), 400

        result = analyze_risks(project_directory)

        if result["status"] == RISK_STATUS_ERROR:
            return jsonify(result), 400

        return jsonify(result), 200

    @app.get("/")
    @app.get("/dashboard")
    def dashboard_page():
        return render_template("dashboard.html")

    @app.post("/api/dashboard/analyze")
    def analyze_dashboard_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return jsonify(build_dashboard_error(error)), 400

        result = analyze_security_dashboard(project_directory)

        if result["status"] == "error":
            return jsonify(result), 400

        result["report_html"] = render_template(
            "security_report.html",
            report=result["report"],
        )

        return jsonify(result), 200

    @app.post("/api/reports/security")
    def export_security_report_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return jsonify(_report_error_payload(error)), 400

        report_format, format_error = _report_format_from_request()
        if format_error is not None:
            return jsonify(_report_error_payload(format_error)), 400

        result = analyze_security_dashboard(project_directory)

        if result["status"] == "error":
            return jsonify(result), 400

        report = result["report"]
        filename = f"{_safe_filename(report['project']['name'])}-security-report"

        if report_format == "html":
            html = render_template("security_report.html", report=report)
            return _attachment_response(
                html,
                mimetype="text/html",
                filename=f"{filename}.html",
            )

        return _attachment_response(
            json.dumps(report, indent=2),
            mimetype="application/json",
            filename=f"{filename}.json",
        )

    @app.route("/api/sbom/download", methods=["GET", "POST"])
    def download_sbom_endpoint():
        project_directory, error = _project_directory_from_request()

        if error is not None:
            return _sbom_error_response(error), 400

        result = generate_sbom(project_directory)

        if result["status"] == SBOM_STATUS_ERROR:
            return jsonify(result), 400

        filename = f"{_safe_filename(result['project_name'])}-sbom.json"
        return _attachment_response(
            json.dumps(result["sbom"], indent=2),
            mimetype="application/json",
            filename=filename,
        )

    init_database(app)

    return app


def _project_directory_from_request():
    """Return the requested project directory and an optional error message."""
    payload, payload_error = _request_payload()

    if payload_error is not None:
        return None, payload_error

    raw_value = None
    for key in ("project_directory", "directory", "path"):
        if key in payload:
            raw_value = payload[key]
            break

    if raw_value is None:
        return None, "project_directory is required"

    if not isinstance(raw_value, str):
        return None, "project_directory must be a string"

    if not raw_value.strip():
        return None, "project_directory must not be empty"

    if len(raw_value) > MAX_PROJECT_DIRECTORY_LENGTH:
        return None, "project_directory is too long"

    if "\x00" in raw_value:
        return None, "project_directory contains invalid characters"

    return raw_value, None


def _request_payload():
    """Return a JSON or form/query object, rejecting malformed JSON objects."""
    payload = request.get_json(silent=True)

    if request.is_json:
        if payload is None:
            if request.get_data(cache=True).strip():
                return None, "request body must be a JSON object"
        elif not isinstance(payload, dict):
            return None, "request body must be a JSON object"

    if not isinstance(payload, dict):
        payload = request.values.to_dict()

    return payload, None


def _is_api_request():
    """Return whether the current request targets an API endpoint."""
    return request.path.startswith(API_PATH_PREFIXES)


def _plain_error_response(message):
    """Build a minimal structured error response without internal details."""
    return jsonify({
        "status": "error",
        "error": message,
        "warnings": [message],
        "errors": [message],
    })


def _sbom_error_response(message):
    """Build a zeroed SBOM error payload for request validation failures."""
    return jsonify({
        "status": SBOM_STATUS_ERROR,
        "source_status": STATUS_ERROR,
        "error": message,
        "project_directory": "",
        "project_name": "",
        "component_count": 0,
        "warnings": [message],
        "sbom": None,
    })


def _vulnerability_error_response(message):
    """Build a zeroed vulnerability error payload for validation failures."""
    return jsonify({
        "status": VULNERABILITY_STATUS_ERROR,
        "source_status": STATUS_ERROR,
        "error": message,
        "project_directory": "",
        "project_name": "",
        "inventory_count": 0,
        "total_dependencies_checked": 0,
        "eligible_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "vulnerable_dependency_count": 0,
        "total_vulnerability_count": 0,
        "vulnerabilities": [],
        "warnings": [message],
        "errors": [message],
    })


def _risk_error_response(message):
    """Build a zeroed risk analysis error payload for validation failures."""
    risk_counts = {
        "Critical": 0,
        "High": 0,
        "Medium": 0,
        "Low": 0,
        "Unknown": 0,
    }
    summary = {
        "total_dependencies": 0,
        "risk_counts": risk_counts,
        "vulnerable_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "incomplete_coverage_dependency_count": 0,
        "project_risk": "Unknown",
        "risk_reason": message,
        "scan_status": "error",
        "scan_coverage": "unavailable",
    }

    return jsonify({
        "status": RISK_STATUS_ERROR,
        "source_status": STATUS_ERROR,
        "error": message,
        "project_directory": "",
        "project_name": "",
        "summary": summary,
        "project_risk": "Unknown",
        "overall_risk": "Unknown",
        "risk_counts": risk_counts,
        "total_dependencies": 0,
        "vulnerable_dependency_count": 0,
        "unresolved_dependency_count": 0,
        "incomplete_coverage_dependency_count": 0,
        "scan_status": "error",
        "scan_coverage": "unavailable",
        "risk_reason": message,
        "dependencies": [],
        "warnings": [message],
        "errors": [message],
    })


def _error_response(message):
    """Build a stable, zeroed error payload for request validation failures."""
    return jsonify({
        "status": STATUS_ERROR,
        "error": message,
        "project_directory": "",
        "project_name": "",
        "manifests": [],
        "dependencies": [],
        "inventory": [],
        "dependency_count": 0,
        "unique_dependency_count": 0,
        "regular_dependency_count": 0,
        "optional_dependency_count": 0,
        "duplicates": [],
        "warnings": [message],
    })


def _report_format_from_request():
    """Return the requested report format and an optional validation error."""
    payload, payload_error = _request_payload()

    if payload_error is not None:
        return None, payload_error

    value = payload.get("format", request.args.get("format", "json"))

    if value is None:
        return "json", None

    if not isinstance(value, str):
        return None, "format must be 'json' or 'html'"

    normalized = value.strip().lower() or "json"

    if normalized not in {"json", "html"}:
        return None, "format must be 'json' or 'html'"

    return normalized, None


def _report_error_payload(message):
    """Build a dashboard-shaped error payload for report export failures."""
    return build_dashboard_error(message)


def _attachment_response(content, *, mimetype, filename):
    """Return downloadable content with an attachment filename."""
    response = Response(content, mimetype=mimetype)
    response.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


def _safe_filename(value):
    """Return a conservative filename stem for downloaded artifacts."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-._")
    return cleaned.lower() or "project"


def run_local_server():
    """Run the local workbench without debug mode or the Werkzeug debugger."""
    application = create_app()
    application.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )


if __name__ == "__main__":
    run_local_server()
