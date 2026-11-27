import json
import re
import secrets
from pathlib import Path

from flask import (
    Flask,
    Response,
    current_app,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config
from database import (
    clear_scan_history,
    clear_login_failures,
    create_local_user,
    delete_scan_history,
    get_scan_history,
    has_local_user,
    init_app as init_database,
    list_scan_history,
    register_login_attempt,
    save_scan_history,
    verify_local_user,
)
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

    history_retention = app.config["HISTORY_RETENTION"]
    if (
        isinstance(history_retention, bool)
        or not isinstance(history_retention, int)
        or history_retention < 1
    ):
        raise ValueError("HISTORY_RETENTION must be a positive integer")

    configured_roots = app.config["ALLOWED_PROJECT_ROOTS"]
    if not isinstance(configured_roots, (list, tuple)) or not configured_roots:
        raise ValueError("ALLOWED_PROJECT_ROOTS must contain existing directories")

    allowed_roots = []
    try:
        for root in configured_roots:
            resolved_root = Path(root).expanduser().resolve(strict=True)
            if not resolved_root.is_dir():
                raise ValueError
            allowed_roots.append(resolved_root)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        raise ValueError(
            "ALLOWED_PROJECT_ROOTS must contain existing directories"
        ) from error
    app.config["ALLOWED_PROJECT_ROOTS"] = tuple(allowed_roots)

    database_path = Path(app.config["DATABASE"])
    app.config["DATABASE"] = database_path
    database_path.parent.mkdir(parents=True, exist_ok=True)

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    @app.context_processor
    def inject_csrf_token():
        return {"csrf_token": _csrf_token("form_csrf")}

    @app.before_request
    def require_local_login():
        if (
            not app.config["AUTH_ENABLED"]
            or request.endpoint in {"health", "login", "setup", "static"}
        ):
            return None

        if not has_local_user():
            if _is_api_request():
                return jsonify(
                    {
                        "status": "error",
                        "error": "initial account setup is required",
                    }
                ), 503
            return redirect(url_for("setup"))

        if session.get("authenticated") is True:
            return None

        if _is_api_request():
            return jsonify(
                {"status": "error", "error": "authentication required"}
            ), 401
        return redirect(url_for("login"))

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

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if has_local_user():
            return redirect(url_for("login"))

        token = _csrf_token("setup_csrf")
        error = None
        if request.method == "POST":
            if not _valid_csrf("setup_csrf", request.form.get("csrf_token")):
                error = "The setup form expired. Reload the page and try again."
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                confirmation = request.form.get("confirm_password", "")

                if not 3 <= len(username) <= 64:
                    error = "Username must be between 3 and 64 characters."
                elif len(password) < 12:
                    error = "Password must be at least 12 characters."
                elif len(password) > 1024:
                    error = "Password must be no more than 1024 characters."
                elif password != confirmation:
                    error = "Passwords do not match."
                elif not create_local_user(
                    username,
                    generate_password_hash(password),
                ):
                    error = "The local account has already been created."
                else:
                    session.clear()
                    session["authenticated"] = True
                    session["username"] = username
                    session.permanent = True
                    return redirect(url_for("dashboard_page"))

        return render_template("setup.html", csrf_token=token, error=error), (
            400 if request.method == "POST" and error else 200
        )

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if not has_local_user():
            return redirect(url_for("setup"))
        if session.get("authenticated") is True:
            return redirect(url_for("dashboard_page"))

        token = _csrf_token("login_csrf")
        error = None
        response_status = 200
        rate_limited = False
        if request.method == "POST":
            if not _valid_csrf("login_csrf", request.form.get("csrf_token")):
                error = "The sign-in form expired. Reload the page and try again."
                response_status = 400
            else:
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                remote_address = request.remote_addr or "unknown"
                retry_after = register_login_attempt(
                    remote_address,
                    max_attempts=app.config["LOGIN_RATE_LIMIT_ATTEMPTS"],
                    window_seconds=app.config["LOGIN_RATE_LIMIT_WINDOW_SECONDS"],
                )
                if retry_after is not None:
                    error = "Too many sign-in attempts. Wait for the rate limit to expire."
                    response_status = 429
                    rate_limited = True
                else:
                    user = verify_local_user(username)
                    if (
                        len(password) > 1024
                        or user is None
                        or not check_password_hash(user["password_hash"], password)
                    ):
                        error = "Invalid username or password."
                        response_status = 401
                    else:
                        clear_login_failures(remote_address)
                        session.clear()
                        session["authenticated"] = True
                        session["username"] = username
                        session.permanent = True
                        return redirect(url_for("dashboard_page"))

        headers = (
            {
                "Retry-After": str(retry_after),
            }
            if rate_limited
            else {}
        )
        return (
            render_template("login.html", csrf_token=token, error=error),
            response_status,
            headers,
        )

    @app.post("/logout")
    def logout():
        if not _valid_csrf("form_csrf", request.form.get("csrf_token")):
            return "The sign-out form expired. Reload the page and try again.", 400
        session.clear()
        return redirect(url_for("login"))

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
        result["history_id"] = save_scan_history(result)

        return jsonify(result), 200

    @app.get("/api/history")
    def scan_history_endpoint():
        return jsonify({"history": list_scan_history()}), 200

    @app.get("/api/history/<int:history_id>")
    def scan_history_item_endpoint(history_id):
        result = get_scan_history(history_id)
        if result is None:
            return jsonify({"error": "scan history item not found"}), 404
        report = result.get("report")
        if isinstance(report, dict):
            result["report_html"] = render_template(
                "security_report.html",
                report=report,
            )
        return jsonify(result), 200

    @app.delete("/api/history/<int:history_id>")
    def delete_scan_history_endpoint(history_id):
        if not delete_scan_history(history_id):
            return jsonify({"error": "scan history item not found"}), 404
        return jsonify({"status": "deleted", "id": history_id}), 200

    @app.delete("/api/history")
    def clear_scan_history_endpoint():
        deleted_count = clear_scan_history()
        return jsonify({"status": "deleted", "count": deleted_count}), 200

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


def _csrf_token(session_key):
    token = session.get(session_key)
    if not isinstance(token, str):
        token = secrets.token_urlsafe(32)
        session[session_key] = token
    return token


def _valid_csrf(session_key, submitted_token):
    expected = session.get(session_key)
    return (
        isinstance(expected, str)
        and isinstance(submitted_token, str)
        and secrets.compare_digest(expected, submitted_token)
    )


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

    normalized_value = raw_value.strip()
    if (
        len(normalized_value) >= 2
        and normalized_value[0] == normalized_value[-1] == '"'
    ):
        normalized_value = normalized_value[1:-1]

    try:
        project_directory = Path(normalized_value).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None, "could not access project directory"

    if not project_directory.is_dir():
        return None, "project path is not a directory"

    allowed_roots = current_app.config["ALLOWED_PROJECT_ROOTS"]
    if not any(
        project_directory == root or project_directory.is_relative_to(root)
        for root in allowed_roots
    ):
        return None, "project directory is outside configured allowed roots"

    return str(project_directory), None


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
