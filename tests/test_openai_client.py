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

from pineai_backend.openai_client import (  # noqa: E402
    OpenAIClient,
    OpenAIClientError,
)


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


class OpenAIClientTests(unittest.TestCase):
    def test_success_uses_strict_schema_and_no_tools(self):
        captured = {}
        structured = {"overall_summary": "ok", "targets": []}

        def opener(api_request, timeout):
            captured["body"] = json.loads(api_request.data.decode("utf-8"))
            captured["authorization"] = api_request.headers["Authorization"]
            return FakeResponse(
                response_body(
                    [{"type": "output_text", "text": json.dumps(structured)}]
                )
            )

        client = OpenAIClient("secret", "gpt-5.6-terra", opener=opener)
        parsed, usage = client.profile({"targets": []}, "en", "device_test")
        self.assertEqual(parsed, structured)
        self.assertEqual(usage["total_tokens"], 15)
        self.assertFalse(captured["body"]["store"])
        self.assertTrue(captured["body"]["text"]["format"]["strict"])
        self.assertNotIn("tools", captured["body"])
        self.assertEqual(captured["authorization"], "Bearer secret")

    def test_refusal(self):
        client = OpenAIClient(
            "secret",
            "model",
            opener=lambda *_args, **_kwargs: FakeResponse(
                response_body([{"type": "refusal", "refusal": "no"}])
            ),
        )
        with self.assertRaises(OpenAIClientError) as raised:
            client.profile({"targets": []}, "en", "device_test")
        self.assertEqual(raised.exception.code, "refusal")

    def test_http_errors_are_classified(self):
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
                client.profile({"targets": []}, "en", "device_test")
            self.assertEqual(raised.exception.code, expected)
            self.assertNotIn("secret upstream body", str(raised.exception))

    def test_timeout_is_classified(self):
        def opener(*_args, **_kwargs):
            raise socket.timeout()

        client = OpenAIClient("secret", "model", opener=opener, max_attempts=1)
        with self.assertRaises(OpenAIClientError) as raised:
            client.profile({"targets": []}, "en", "device_test")
        self.assertEqual(raised.exception.code, "network_error")

    def test_invalid_json_output_is_rejected(self):
        client = OpenAIClient(
            "secret",
            "model",
            opener=lambda *_args, **_kwargs: FakeResponse(
                response_body([{"type": "output_text", "text": "not json"}])
            ),
        )
        with self.assertRaises(OpenAIClientError) as raised:
            client.profile({"targets": []}, "en", "device_test")
        self.assertEqual(raised.exception.code, "invalid_response")

    def test_advisor_uses_strict_schema_and_no_tools(self):
        captured = {}
        structured = {"targets": []}

        def opener(api_request, timeout):
            captured["body"] = json.loads(api_request.data.decode("utf-8"))
            return FakeResponse(
                response_body(
                    [{"type": "output_text", "text": json.dumps(structured)}]
                )
            )

        client = OpenAIClient("secret", "gpt-5.6-terra", opener=opener)
        parsed, _usage = client.advise({"targets": []}, "fi", "device_test")
        self.assertEqual(parsed, structured)
        self.assertEqual(
            captured["body"]["text"]["format"]["name"], "pineai_attack_paths"
        )
        self.assertTrue(captured["body"]["text"]["format"]["strict"])
        self.assertFalse(captured["body"]["store"])
        self.assertNotIn("tools", captured["body"])


if __name__ == "__main__":
    unittest.main()
