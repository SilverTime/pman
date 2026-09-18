import json
import unittest
from unittest.mock import patch

from pman.client import ClientError, DaemonClient, _normalize_json_value
from pman.protocol import ERROR_INVALID_REQUEST


class ClientEncodingTest(unittest.TestCase):
    def test_recovers_surrogate_escaped_utf8_tool_argument(self):
        expected_alias = "jekins Release和基线"
        malformed_alias = expected_alias.encode("utf-8").decode(
            "ascii", "surrogateescape"
        )

        request = _normalize_json_value(
            {
                "site": malformed_alias,
                "query": {"任务": ["构建"]},
            }
        )

        self.assertEqual(request["site"], expected_alias)
        self.assertEqual(request["query"], {"任务": ["构建"]})

    def test_rejects_incomplete_surrogate_escaped_utf8(self):
        with self.assertRaises(ClientError) as raised:
            _normalize_json_value({"site": "jenkins\udcbf"})

        self.assertEqual(raised.exception.error_code, ERROR_INVALID_REQUEST)

    def test_daemon_request_sends_recovered_alias_as_utf8(self):
        expected_alias = "jekins Release和基线"
        malformed_alias = expected_alias.encode("utf-8").decode(
            "ascii", "surrogateescape"
        )

        class Response:
            def read(self):
                return b'{"ok": true, "protocol": "pman", "protocol_version": 2}'

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

        with patch("pman.client.urllib.request.urlopen", return_value=Response()) as urlopen:
            result = DaemonClient("http://127.0.0.1:9777", "test-token").http(
                malformed_alias,
                "GET",
                "/api/json",
            )

        outbound = json.loads(urlopen.call_args.args[0].data.decode("utf-8"))
        self.assertTrue(result["ok"])
        self.assertEqual(outbound["site"], expected_alias)


if __name__ == "__main__":
    unittest.main()
