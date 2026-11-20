import re

from app import create_app
from database import list_scan_history, save_scan_history
from werkzeug.security import check_password_hash


def _client(tmp_path):
    app = create_app(
        {
            "TESTING": True,
            "DATABASE": tmp_path / "auth-history.db",
            "AUTH_ENABLED": True,
            "HISTORY_RETENTION": 50,
        }
    )
    return app, app.test_client()


def _csrf_token(response):
    match = re.search(
        r'name="csrf_token" value="([^"]+)"',
        response.get_data(as_text=True),
    )
    assert match is not None
    return match.group(1)


def _setup_account(client, username="local-user", password="correct horse battery"):
    response = client.get("/setup")
    assert response.status_code == 200
    return client.post(
        "/setup",
        data={
            "csrf_token": _csrf_token(response),
            "username": username,
            "password": password,
            "confirm_password": password,
        },
        follow_redirects=False,
    )


def _login(client, username="local-user", password="correct horse battery"):
    response = client.get("/login")
    return client.post(
        "/login",
        data={
            "csrf_token": _csrf_token(response),
            "username": username,
            "password": password,
        },
        follow_redirects=False,
    )


def test_first_run_requires_account_setup_and_protects_apis(tmp_path):
    _, client = _client(tmp_path)

    dashboard = client.get("/")
    api = client.get("/api/history")
    health = client.get("/health")

    assert dashboard.status_code == 302
    assert dashboard.headers["Location"].endswith("/setup")
    assert api.status_code == 503
    assert api.get_json()["error"] == "initial account setup is required"
    assert health.status_code == 200


def test_setup_validates_password_and_csrf_token(tmp_path):
    _, client = _client(tmp_path)
    page = client.get("/setup")
    csrf_token = _csrf_token(page)

    invalid_password = client.post(
        "/setup",
        data={
            "csrf_token": csrf_token,
            "username": "local-user",
            "password": "short",
            "confirm_password": "short",
        },
    )
    invalid_csrf = client.post(
        "/setup",
        data={
            "csrf_token": "wrong-token",
            "username": "local-user",
            "password": "correct horse battery",
            "confirm_password": "correct horse battery",
        },
    )

    assert invalid_password.status_code == 400
    assert "at least 12 characters" in invalid_password.get_data(as_text=True)
    assert invalid_csrf.status_code == 400
    assert "form expired" in invalid_csrf.get_data(as_text=True)


def test_single_account_setup_login_logout_and_session_security(tmp_path):
    app, client = _client(tmp_path)

    assert _setup_account(client).status_code == 302
    assert client.get("/").status_code == 200

    with app.app_context():
        from database import get_db

        row = get_db().execute(
            "SELECT username, password_hash FROM local_user"
        ).fetchone()
        assert row["username"] == "local-user"
        assert row["password_hash"] != "correct horse battery"
        assert check_password_hash(
            row["password_hash"],
            "correct horse battery",
        )

    setup_again = client.get("/setup")
    assert setup_again.status_code == 302
    assert setup_again.headers["Location"].endswith("/login")

    with client.session_transaction() as browser_session:
        form_csrf = browser_session["form_csrf"]
    logout = client.post("/logout", data={"csrf_token": form_csrf})
    assert logout.status_code == 302
    assert client.get("/").headers["Location"].endswith("/login")
    assert client.get("/api/history").status_code == 401

    wrong_login = _login(client, password="incorrect password")
    assert wrong_login.status_code == 401
    assert "Invalid username or password" in wrong_login.get_data(as_text=True)

    successful_login = _login(client)
    assert successful_login.status_code == 302
    assert client.get("/").status_code == 200


def test_dashboard_scan_is_saved_and_history_can_be_loaded_and_deleted(
    tmp_path,
):
    _, client = _client(tmp_path)
    _setup_account(client)

    project = tmp_path / "small project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")

    scan = client.post(
        "/api/dashboard/analyze",
        json={"project_directory": str(project)},
    )

    assert scan.status_code == 200
    result = scan.get_json()
    history_id = result["history_id"]
    assert result["status"] == "partial"

    history = client.get("/api/history").get_json()["history"]
    assert len(history) == 1
    assert history[0]["id"] == history_id
    assert history[0]["project_name"] == project.name

    saved = client.get(f"/api/history/{history_id}")
    assert saved.status_code == 200
    saved_result = saved.get_json()
    assert saved_result["history_id"] == history_id
    assert saved_result["report"]["inventory"][0]["package_name"] == "requests"
    assert "Dependency security assessment" in saved_result["report_html"]

    deleted = client.delete(f"/api/history/{history_id}")
    assert deleted.status_code == 200
    assert client.get(f"/api/history/{history_id}").status_code == 404


def test_history_retains_only_the_most_recent_fifty_scans(tmp_path):
    app, _ = _client(tmp_path)
    payload = {
        "status": "partial",
        "project": {"name": "project", "directory": "C:/project"},
        "summary": {
            "total_dependencies": 1,
            "total_vulnerabilities": 0,
            "project_risk": "Unknown",
        },
        "dependencies": [{"package_name": "requests"}],
        "vulnerabilities": [],
        "risk": {"dependencies": [{"package_name": "requests"}]},
        "report": {"inventory": [{"package_name": "requests"}]},
    }

    with app.app_context():
        for index in range(51):
            payload["project"] = {
                "name": f"project-{index}",
                "directory": f"C:/project-{index}",
            }
            save_scan_history(payload)
        history = list_scan_history()

    assert len(history) == 50
    assert history[0]["project_name"] == "project-50"
    assert history[-1]["project_name"] == "project-1"


def test_clear_history_removes_all_saved_scans(tmp_path):
    _, client = _client(tmp_path)
    _setup_account(client)

    project = tmp_path / "small project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests>=2.31\n", encoding="utf-8")
    response = client.post(
        "/api/dashboard/analyze",
        json={"project_directory": str(project)},
    )
    assert response.status_code == 200

    cleared = client.delete("/api/history")

    assert cleared.status_code == 200
    assert cleared.get_json() == {"status": "deleted", "count": 1}
    assert client.get("/api/history").get_json()["history"] == []


def test_history_retention_must_be_positive(tmp_path):
    try:
        create_app(
            {
                "TESTING": True,
                "DATABASE": tmp_path / "invalid-retention.db",
                "HISTORY_RETENTION": 0,
            }
        )
    except ValueError as error:
        assert str(error) == "HISTORY_RETENTION must be a positive integer"
    else:
        raise AssertionError("invalid history retention should be rejected")
