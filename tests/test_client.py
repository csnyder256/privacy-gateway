"""The HTTP client must turn every non-2xx (and every non-JSON 2xx) into its own error.

``_raise`` exists so a caller can write ``except PrivacyGatewayError`` and read the
status out of the message. It read the body with ``response.json().get("detail", …)``,
which holds only for a JSON *object*: a body of ``null``, ``[...]`` or ``"…"`` made
``.get`` raise ``AttributeError`` and the status was lost, and a 2xx whose body was
not JSON escaped as a bare ``JSONDecodeError``. ``packages/client`` reads the same
responses into ``PrivacyGatewayError``; these tests pin the Python side to it.
"""

from __future__ import annotations

import asyncio

import httpx
import pytest

from privacy_gateway import AsyncPrivacyGatewayClient, PrivacyGatewayClient, PrivacyGatewayError


def _client(
    status: int, body: bytes, content_type: str = "application/json"
) -> PrivacyGatewayClient:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status, content=body, headers={"content-type": content_type}, request=request
        )

    return PrivacyGatewayClient(transport=httpx.MockTransport(handler))


@pytest.mark.parametrize(
    ("status", "body", "content_type"),
    [
        # A JSON body that is not an object: `.get` raised AttributeError on each.
        (502, b"null", "application/json"),
        (503, b'[{"detail": "down"}]', "application/json"),
        (429, b'"slow down"', "application/json"),
        # Bodies that were never JSON at all.
        (500, b"Internal Server Error", "text/plain"),
        (502, b"<html><body>Bad Gateway</body></html>", "text/html"),
        (503, b"", "text/plain"),
    ],
)
def test_every_failure_arrives_as_a_structured_error(status, body, content_type):
    with (
        _client(status, body, content_type) as client,
        pytest.raises(PrivacyGatewayError) as caught,
    ):
        client.create_session()

    assert str(caught.value).startswith(f"gateway returned {status}: ")


def test_a_json_scalar_body_reports_the_status_not_an_attribute_error():
    # `null` parses, and `.get` on it raised `AttributeError` with the status lost.
    # The message carries the body verbatim, exactly as `packages/client` reports it.
    with (
        _client(502, b"null") as client,
        pytest.raises(PrivacyGatewayError, match=r"^gateway returned 502: null$"),
    ):
        client.transform("Email a@b.com")


def test_an_empty_failure_body_still_names_the_request():
    with (
        _client(503, b"", "text/plain") as client,
        pytest.raises(PrivacyGatewayError, match=r"^gateway returned 503: request failed$"),
    ):
        client.summary("session")


def test_a_plain_text_failure_keeps_the_body_verbatim():
    with (
        _client(500, b"Internal Server Error\n", "text/plain") as client,
        pytest.raises(PrivacyGatewayError, match=r"^gateway returned 500: Internal Server Error$"),
    ):
        client.create_session()


def test_a_fastapi_validation_detail_is_serialized_as_json():
    body = b'{"detail": [{"loc": ["body", "preset"], "msg": "bad"}]}'
    with _client(422, body) as client, pytest.raises(PrivacyGatewayError) as caught:
        client.create_session()

    assert str(caught.value) == (
        'gateway returned 422: [{"loc": ["body", "preset"], "msg": "bad"}]'
    )


def test_a_json_detail_string_is_reported_as_itself():
    with (
        _client(409, b'{"detail": "session already closed"}') as client,
        pytest.raises(PrivacyGatewayError, match=r"^gateway returned 409: session already closed$"),
    ):
        client.create_session()


def test_a_success_whose_body_is_not_json_is_a_structured_error():
    """The Python twin of the ``SyntaxError`` the TypeScript client used to throw."""
    with (
        _client(200, b"<html>not json</html>", "text/html") as client,
        pytest.raises(
            PrivacyGatewayError, match=r"^gateway returned 200: response body was not JSON$"
        ),
    ):
        client.create_session()


def test_the_async_client_reads_a_failure_the_same_way():
    async def exercise() -> str:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                503,
                content=b"null",
                headers={"content-type": "application/json"},
                request=request,
            )

        async with AsyncPrivacyGatewayClient(transport=httpx.MockTransport(handler)) as client:
            with pytest.raises(PrivacyGatewayError) as caught:
                await client.create_session()
            return str(caught.value)

    assert asyncio.run(exercise()) == "gateway returned 503: null"
