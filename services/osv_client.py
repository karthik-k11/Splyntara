"""Small client for the public OSV vulnerability API.

The batch endpoint returns only vulnerability identifiers. Full advisories are
fetched one at a time from the vulnerability endpoint and cached by the caller.
No credentials are required or stored by this module.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import requests

OSV_API_BASE_URL = "https://api.osv.dev"
BATCH_QUERY_PATH = "/v1/querybatch"
VULNERABILITY_PATH = "/v1/vulns/{vulnerability_id}"
DEFAULT_TIMEOUT_SECONDS = 10.0
MAX_BATCH_SIZE = 1_000
MAX_PAGES_PER_BATCH = 20

__all__ = [
    "OSV_API_BASE_URL",
    "BATCH_QUERY_PATH",
    "VULNERABILITY_PATH",
    "DEFAULT_TIMEOUT_SECONDS",
    "MAX_BATCH_SIZE",
    "OSVClient",
    "OSVError",
    "OSVTimeoutError",
    "OSVConnectionError",
    "OSVRateLimitError",
    "OSVServerError",
    "OSVRequestError",
    "OSVInvalidResponseError",
]


class OSVError(Exception):
    """Base class for expected OSV API failures."""


class OSVTimeoutError(OSVError):
    """The OSV request exceeded the configured timeout."""


class OSVConnectionError(OSVError):
    """The OSV service could not be reached."""


class OSVRateLimitError(OSVError):
    """OSV returned HTTP 429."""


class OSVServerError(OSVError):
    """OSV returned an HTTP 5xx response."""


class OSVRequestError(OSVError):
    """OSV returned another non-success HTTP response."""


class OSVInvalidResponseError(OSVError):
    """OSV returned a response that did not match the expected schema."""


class OSVClient:
    """Client for the two OSV endpoints used by the vulnerability scanner."""

    def __init__(
        self,
        *,
        base_url: str = OSV_API_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def query_batch(
        self,
        queries: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """Return vulnerability references for each package/version query.

        The OSV batch endpoint returns one result per query, in the same order.
        Large inputs are split into batches of at most ``MAX_BATCH_SIZE``. Each
        individual result can include a ``next_page_token``; those queries are
        repeated until their pagination is exhausted.
        """
        if not isinstance(queries, list):
            raise TypeError("queries must be a list")

        if not queries:
            return []

        results: list[list[dict[str, Any]]] = []

        for start in range(0, len(queries), MAX_BATCH_SIZE):
            chunk = queries[start:start + MAX_BATCH_SIZE]
            results.extend(self._query_batch_chunk(chunk))

        return results

    def get_vulnerability(self, vulnerability_id: str) -> dict[str, Any]:
        """Fetch a full OSV advisory by ID."""
        if not isinstance(vulnerability_id, str) or not vulnerability_id.strip():
            raise OSVRequestError("OSV vulnerability ID must be a non-empty string")

        encoded_id = quote(vulnerability_id.strip(), safe="")
        path = VULNERABILITY_PATH.format(vulnerability_id=encoded_id)
        response = self._request("GET", path)
        payload = self._response_json(response)

        if not isinstance(payload, dict):
            raise OSVInvalidResponseError(
                "OSV vulnerability response was not a JSON object"
            )

        response_id = payload.get("id")
        if not isinstance(response_id, str) or not response_id.strip():
            raise OSVInvalidResponseError(
                "OSV vulnerability response did not contain a valid ID"
            )

        if response_id.strip() != vulnerability_id.strip():
            raise OSVInvalidResponseError(
                "OSV vulnerability response ID did not match the requested ID"
            )

        return payload

    def _query_batch_chunk(
        self,
        queries: list[dict[str, Any]],
    ) -> list[list[dict[str, Any]]]:
        """Query one batch chunk, following per-query pagination tokens."""
        collected: list[list[dict[str, Any]]] = [[] for _ in queries]
        pending: dict[int, dict[str, Any]] = {
            index: dict(query) for index, query in enumerate(queries)
        }
        pages = 0

        while pending:
            pages += 1
            if pages > MAX_PAGES_PER_BATCH:
                raise OSVInvalidResponseError(
                    "OSV batch response pagination did not terminate"
                )

            indexes = list(pending)
            payload = {"queries": [pending[index] for index in indexes]}
            response = self._request("POST", BATCH_QUERY_PATH, json=payload)
            body = self._response_json(response)
            raw_results = body.get("results") if isinstance(body, dict) else None

            if not isinstance(raw_results, list) or len(raw_results) != len(indexes):
                raise OSVInvalidResponseError(
                    "OSV batch response did not contain one result per query"
                )

            next_pending: dict[int, dict[str, Any]] = {}

            for index, raw_result in zip(indexes, raw_results):
                if not isinstance(raw_result, dict):
                    raise OSVInvalidResponseError(
                        "OSV batch result was not a JSON object"
                    )

                raw_vulns = raw_result.get("vulns", [])
                if raw_vulns is None:
                    raw_vulns = []

                if not isinstance(raw_vulns, list):
                    raise OSVInvalidResponseError(
                        "OSV batch result contained an invalid vulnerabilities list"
                    )

                for raw_vuln in raw_vulns:
                    if not isinstance(raw_vuln, dict):
                        raise OSVInvalidResponseError(
                            "OSV batch vulnerability reference was not a JSON object"
                        )

                    vulnerability_id = raw_vuln.get("id")
                    if (
                        not isinstance(vulnerability_id, str)
                        or not vulnerability_id.strip()
                    ):
                        raise OSVInvalidResponseError(
                            "OSV batch vulnerability reference had no valid ID"
                        )

                    modified = raw_vuln.get("modified")
                    collected[index].append(
                        {
                            "id": vulnerability_id.strip(),
                            "modified": modified.strip()
                            if isinstance(modified, str) and modified.strip()
                            else None,
                        }
                    )

                next_page_token = raw_result.get("next_page_token")
                if next_page_token is not None:
                    if (
                        not isinstance(next_page_token, str)
                        or not next_page_token.strip()
                    ):
                        raise OSVInvalidResponseError(
                            "OSV batch result contained an invalid page token"
                        )

                    next_pending[index] = {
                        **pending[index],
                        "page_token": next_page_token,
                    }

            pending = next_pending

        return collected

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.base_url}{path}"

        try:
            if method == "POST":
                response = requests.post(url, timeout=self.timeout, **kwargs)
            else:
                response = requests.get(url, timeout=self.timeout, **kwargs)
        except requests.Timeout as error:
            raise OSVTimeoutError("OSV request timed out") from error
        except requests.ConnectionError as error:
            raise OSVConnectionError("could not connect to the OSV service") from error
        except requests.RequestException as error:
            raise OSVError("OSV request failed") from error

        if response.status_code == 429:
            raise OSVRateLimitError("OSV rate limit was exceeded")

        if response.status_code >= 500:
            raise OSVServerError(
                f"OSV server error (HTTP {response.status_code})"
            )

        if response.status_code >= 400:
            raise OSVRequestError(
                f"OSV request failed (HTTP {response.status_code})"
            )

        return response

    def _response_json(self, response: requests.Response) -> Any:
        try:
            return response.json()
        except ValueError as error:
            raise OSVInvalidResponseError("OSV returned invalid JSON") from error
