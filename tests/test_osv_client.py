"""Tests for the OSV HTTP client."""

from unittest.mock import patch

import pytest
import requests

from services import osv_client
from services.osv_client import (
    DEFAULT_TIMEOUT_SECONDS,
    OSVClient,
    OSVConnectionError,
    OSVInvalidResponseError,
    OSVRateLimitError,
    OSVRequestError,
    OSVServerError,
    OSVTimeoutError,
)

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULNERABILITY_URL = "https://api.osv.dev/v1/vulns"


class FakeResponse:
    def __init__(self, status_code=200, payload=None, invalid_json=False):
        self.status_code = status_code
        self.payload = payload
        self.invalid_json = invalid_json

    def json(self):
        if self.invalid_json:
            raise ValueError("invalid JSON")
        return self.payload


def _query(name="requests", version="2.31.0"):
    return {
        "package": {"name": name, "ecosystem": "PyPI"},
        "version": version,
    }


def test_query_batch_posts_queries_and_returns_vulnerability_references():
    queries = [_query(), _query("flask", "3.0.0")]
    response = FakeResponse(
        payload={
            "results": [
                {"vulns": [{"id": "GHSA-1111", "modified": "2026-01-01T00:00:00Z"}]},
                {},
            ]
        }
    )

    with patch("services.osv_client.requests.post", return_value=response) as post:
        result = OSVClient().query_batch(queries)

    assert result == [
        [{"id": "GHSA-1111", "modified": "2026-01-01T00:00:00Z"}],
        [],
    ]
    post.assert_called_once_with(
        BATCH_URL,
        timeout=DEFAULT_TIMEOUT_SECONDS,
        json={"queries": queries},
    )


def test_query_batch_returns_empty_list_for_no_queries():
    with patch("services.osv_client.requests.post") as post:
        result = OSVClient().query_batch([])

    assert result == []
    post.assert_not_called()


def test_query_batch_chunks_large_query_sets(monkeypatch):
    monkeypatch.setattr(osv_client, "MAX_BATCH_SIZE", 2)
    queries = [_query(), _query("flask", "3.0.0"), _query("pytest", "8.0.0")]
    responses = [
        FakeResponse(payload={"results": [{}, {}]}),
        FakeResponse(payload={"results": [{}]}),
    ]

    with patch(
        "services.osv_client.requests.post",
        side_effect=responses,
    ) as post:
        result = OSVClient().query_batch(queries)

    assert result == [[], [], []]
    assert post.call_count == 2
    assert post.call_args_list[0].kwargs["json"] == {"queries": queries[:2]}
    assert post.call_args_list[1].kwargs["json"] == {"queries": queries[2:]}


def test_query_batch_follows_per_query_pagination():
    first = FakeResponse(
        payload={
            "results": [
                {
                    "vulns": [{"id": "GHSA-1111"}],
                    "next_page_token": "next-page",
                }
            ]
        }
    )
    second = FakeResponse(
        payload={"results": [{"vulns": [{"id": "GHSA-2222"}]}]}
    )

    with patch(
        "services.osv_client.requests.post",
        side_effect=[first, second],
    ) as post:
        result = OSVClient().query_batch([_query()])

    assert result == [[{"id": "GHSA-1111", "modified": None}, {"id": "GHSA-2222", "modified": None}]]
    assert post.call_args_list[1].kwargs["json"]["queries"][0]["page_token"] == "next-page"


def test_get_vulnerability_fetches_full_advisory():
    payload = {"id": "GHSA-1111", "summary": "Example vulnerability"}
    response = FakeResponse(payload=payload)

    with patch("services.osv_client.requests.get", return_value=response) as get:
        result = OSVClient().get_vulnerability("GHSA-1111")

    assert result == payload
    get.assert_called_once_with(
        f"{VULNERABILITY_URL}/GHSA-1111",
        timeout=DEFAULT_TIMEOUT_SECONDS,
    )


@pytest.mark.parametrize(
    ("exception", "error_type"),
    [
        (requests.Timeout(), OSVTimeoutError),
        (requests.ConnectionError(), OSVConnectionError),
    ],
)
def test_transport_failures_are_mapped_to_domain_errors(exception, error_type):
    with patch("services.osv_client.requests.post", side_effect=exception):
        with pytest.raises(error_type):
            OSVClient().query_batch([_query()])


@pytest.mark.parametrize(
    ("status_code", "error_type"),
    [
        (429, OSVRateLimitError),
        (500, OSVServerError),
        (503, OSVServerError),
        (404, OSVRequestError),
    ],
)
def test_http_failures_are_mapped_to_domain_errors(status_code, error_type):
    response = FakeResponse(status_code=status_code, payload={})

    with patch("services.osv_client.requests.post", return_value=response):
        with pytest.raises(error_type):
            OSVClient().query_batch([_query()])


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(invalid_json=True),
        FakeResponse(payload=[]),
        FakeResponse(payload={}),
        FakeResponse(payload={"results": []}),
        FakeResponse(payload={"results": [{"vulns": "not-a-list"}]}),
        FakeResponse(payload={"results": [{"vulns": [{"modified": "missing-id"}]}]}),
    ],
)
def test_invalid_batch_responses_are_rejected(response):
    with patch("services.osv_client.requests.post", return_value=response):
        with pytest.raises(OSVInvalidResponseError):
            OSVClient().query_batch([_query()])


def test_invalid_vulnerability_response_is_rejected():
    response = FakeResponse(payload={"summary": "missing id"})

    with patch("services.osv_client.requests.get", return_value=response):
        with pytest.raises(OSVInvalidResponseError):
            OSVClient().get_vulnerability("GHSA-1111")
