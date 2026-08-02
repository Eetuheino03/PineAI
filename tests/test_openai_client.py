import json
import socket
import sys
import unittest
from email.message import Message
from io import BytesIO
from pathlib import Path
from urllib import error


ASSETS = (
    Path(__file__).resolve().parents[1]
    / "projects"
    / "PineAI"
    / "src"
    / "assets"
)
sys.path.insert(0, str(ASSETS))

from pineai_backend import __version__  # noqa: E402
from pineai_backend.openai_client import (  # noqa: E402
    MAX_RESPONSE_BYTES,
    OpenAIClient,
    OpenAIClientError,
)


class FakeResponse:
    def __init__(self, body, headers=None, encoded=False):
        self.body = body if encoded else json.dumps(body).encode("utf-8")
        self.headers = headers or Message()
        self.read_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size=-1):
        self.read_count += 1
        return self.body if size < 0 else self.body[:size]


def response_body(content):
    return {
        "output": [{"content": content}],
        "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
    }


def valid_analysis():
    return {
        "summary": "Observed deterministic changes.",
        "finding_explanations": [],
        "report_sections": {
            "executive_summary": "Summary",
            "technical_summary": "Technical",
            "change_summary": "Changes",
            "limitations": [],
        },
    }


class OpenAIClientTests(unittest.TestCase):
    def test_assurance_analysis_is_strict_stored_false_and_has_no_tools(self):
        captured = {}

        def opener(api_request, timeout):
            captured["body"] = json.loads(api_request.data.decode("utf-8"))
            captured["authorization"] = api_request.headers["Authorization"]
            captured["user_agent"] = api_request.headers["User-agent"]
            return FakeResponse(
                response_body(
                    [{"type": "output_text", "text": json.dumps(valid_analysis())}]
                )
            )

        client = OpenAIClient("secret", "gpt-5.6-terra", opener=opener)
        parsed, usage = client.analyze_assurance(
            {"findings": []}, "fi", "device_test"
        )
        self.assertEqual(parsed, valid_analysis())
        self.assertEqual(usage["total_tokens"], 15)
        body = captured["body"]
        self.assertFalse(body["store"])
        self.assertEqual(body["reasoning"], {"effort": "low"})
        self.assertTrue(body["text"]["format"]["strict"])
        self.assertEqual(
            body["text"]["format"]["name"], "pineai_assurance_analysis"
        )
        self.assertNotIn("tools", body)
        self.assertEqual(captured["authorization"], "Bearer secret")
        self.assertEqual(captured["user_agent"], "PineAI/{0}".format(__version__))
        self.assertIn("authoritative", body["input"][0]["content"])

    def test_refusal(self):
        client = OpenAIClient(
            "secret",
            "model",
            opener=lambda *_args, **_kwargs: FakeResponse(
                response_body([{"type": "refusal", "refusal": "no"}])
            ),
        )
        with self.assertRaises(OpenAIClientError) as raised:
            client.analyze_assurance({}, "en", "device_test")
        self.assertEqual(raised.exception.code, "refusal")

    def test_http_errors_are_classified_without_leaking_body(self):
        for status, expected in (
            (401, "authentication_error"),
            (429, "rate_limited"),
            (500, "upstream_error"),
        ):
            headers = Message()
            headers["Retry-After"] = "0"

            def opener(*_args, **_kwargs):
                raise error.HTTPError(
                    "https://api.openai.com/v1/responses",
                    status,
                    "error",
                    headers,
                    BytesIO(b"secret upstream body"),
                )

            client = OpenAIClient(
                "secret", "model", opener=opener, max_attempts=1
            )
            with self.assertRaises(OpenAIClientError) as raised:
                client.analyze_assurance({}, "en", "device_test")
            self.assertEqual(raised.exception.code, expected)
            self.assertNotIn("secret upstream body", str(raised.exception))

    def test_timeout_and_invalid_json_are_classified(self):
        client = OpenAIClient(
            "secret",
            "model",
            opener=lambda *_args, **_kwargs: (_ for _ in ()).throw(socket.timeout()),
            max_attempts=1,
        )
        with self.assertRaises(OpenAIClientError) as timeout:
            client.analyze_assurance({}, "en", "device_test")
        self.assertEqual(timeout.exception.code, "network_error")

        invalid = OpenAIClient(
            "secret",
            "model",
            opener=lambda *_args, **_kwargs: FakeResponse(
                response_body([{"type": "output_text", "text": "not json"}])
            ),
        )
        with self.assertRaises(OpenAIClientError) as response:
            invalid.analyze_assurance({}, "en", "device_test")
        self.assertEqual(response.exception.code, "invalid_response")

    def test_oversized_responses_are_rejected_before_json_parsing(self):
        declared_headers = Message()
        declared_headers["Content-Length"] = str(MAX_RESPONSE_BYTES + 1)
        declared = FakeResponse(b"{}", headers=declared_headers, encoded=True)

        oversized = b"x" * (MAX_RESPONSE_BYTES + 1)
        undeclared = FakeResponse(oversized, encoded=True)

        chunked_headers = Message()
        chunked_headers["Transfer-Encoding"] = "chunked"
        chunked = FakeResponse(
            oversized, headers=chunked_headers, encoded=True
        )

        for response in (declared, undeclared, chunked):
            client = OpenAIClient(
                "secret",
                "model",
                opener=lambda *_args, _response=response, **_kwargs: _response,
                max_attempts=1,
            )
            with self.assertRaises(OpenAIClientError) as raised:
                client.analyze_assurance({}, "en", "device_test")
            self.assertEqual(raised.exception.code, "response_too_large")

        self.assertEqual(declared.read_count, 0)
        self.assertEqual(undeclared.read_count, 1)
        self.assertEqual(chunked.read_count, 1)


if __name__ == "__main__":
    unittest.main()
