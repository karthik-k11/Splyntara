def test_application_creation_succeeds(app):
    assert app is not None
    assert app.name == "app"


def test_health_returns_http_200(client):
    response = client.get("/health")

    assert response.status_code == 200


def test_health_response_contains_expected_fields(client):
    payload = client.get("/health").get_json()

    assert payload["status"] == "ok"
    assert payload["application"] == "Splyntara"
