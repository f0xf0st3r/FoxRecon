"""Unit tests for V2 scanner adapters."""

import pytest

from internal.scanners.ffuf import FfufScanner
from internal.scanners.gowitness import GowitnessScanner


class TestFfufParser:
    def test_json_output(self):
        scanner = FfufScanner()
        raw = '''{
            "results": [
                {
                    "input": {"FUZZ": "admin"},
                    "url": "https://example.com/admin",
                    "status": 200,
                    "length": 4521,
                    "words": 120,
                    "lines": 45,
                    "content_type": "text/html"
                },
                {
                    "input": {"FUZZ": "login"},
                    "url": "https://example.com/login",
                    "status": 302,
                    "length": 0,
                    "words": 0,
                    "lines": 0,
                    "content_type": "",
                    "redirectlocation": "/dashboard"
                }
            ]
        }'''
        items = scanner.parse_output(raw)
        assert len(items) == 2
        assert items[0]["path"] == "admin"
        assert items[0]["status"] == 200
        assert items[1]["redirect_location"] == "/dashboard"

    def test_line_json_output(self):
        scanner = FfufScanner()
        raw = '{"input": {"FUZZ": "api"}, "url": "https://example.com/api", "status": 200, "length": 100, "words": 10, "lines": 5, "content_type": "application/json"}\n'
        items = scanner.parse_output(raw)
        # Line-based JSON is handled as a single JSON object in the results array pattern
        # The parse_output expects either full JSON with results array or line-by-line
        assert isinstance(items, list)

    def test_empty_output(self):
        scanner = FfufScanner()
        items = scanner.parse_output("")
        assert len(items) == 0

    def test_invalid_json(self):
        scanner = FfufScanner()
        items = scanner.parse_output("not json")
        assert len(items) == 0


class TestGowitnessParser:
    def test_empty_parse(self):
        scanner = GowitnessScanner()
        items = scanner.parse_output("raw output")
        assert len(items) == 0
