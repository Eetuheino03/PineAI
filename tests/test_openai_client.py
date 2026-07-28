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
from pineai_backend.openai_client import OpenAIClient, OpenAIClientError  # noqa: E402


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.body


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


if __name__ == "__main__":
    unittest.main()
