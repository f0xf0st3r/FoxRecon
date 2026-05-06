"""Unit tests for scanner adapters."""

import pytest

from internal.scanners.subfinder import SubfinderScanner
from internal.scanners.httpx import HttpxScanner
from internal.scanners.naabu import NaabuScanner
from internal.scanners.nuclei import NucleiScanner


class TestSubfinderParser:
    def test_json_output(self):
        scanner = SubfinderScanner()
        raw = '{"host":"api.example.com","source":"crtsh","resolved":"1.2.3.4"}\n'
        raw += '{"host":"www.example.com","source":"shodan","resolved":"5.6.7.8"}\n'
        items = scanner.parse_output(raw)
        assert len(items) == 2
        assert items[0]["domain"] == "api.example.com"
        assert items[0]["source"] == "crtsh"

    def test_plain_output(self):
        scanner = SubfinderScanner()
        raw = "api.example.com\nwww.example.com\n"
        items = scanner.parse_output(raw)
        assert len(items) == 2

    def test_deduplication(self):
        scanner = SubfinderScanner()
        raw = "api.example.com\napi.example.com\nwww.example.com\n"
        items = scanner.parse_output(raw)
        assert len(items) == 2

    def test_empty_output(self):
        scanner = SubfinderScanner()
        items = scanner.parse_output("")
        assert len(items) == 0


class TestHttpxParser:
    def test_json_output(self):
        scanner = HttpxScanner()
        raw = '{"url":"https://api.example.com","host":"api.example.com","a":["1.2.3.4"],"status_code":200,"title":"API","tech":["Nginx"]}\n'
        items = scanner.parse_output(raw)
        assert len(items) == 1
        assert items[0]["status_code"] == 200
        assert "Nginx" in items[0]["tech"]

    def test_empty_output(self):
        scanner = HttpxScanner()
        items = scanner.parse_output("")
        assert len(items) == 0


class TestNaabuParser:
    def test_json_output(self):
        scanner = NaabuScanner()
        raw = '{"host":"example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}\n'
        raw += '{"host":"example.com","ip":"1.2.3.4","port":443,"protocol":"tcp"}\n'
        items = scanner.parse_output(raw)
        assert len(items) == 2
        assert items[0]["port"] == 80

    def test_deduplication(self):
        scanner = NaabuScanner()
        raw = '{"host":"example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}\n'
        raw += '{"host":"example.com","ip":"1.2.3.4","port":80,"protocol":"tcp"}\n'
        items = scanner.parse_output(raw)
        assert len(items) == 1

    def test_plain_output(self):
        scanner = NaabuScanner()
        raw = "example.com:80\nexample.com:443\n"
        items = scanner.parse_output(raw)
        assert len(items) == 2


class TestNucleiParser:
    def test_json_output(self):
        scanner = NucleiScanner()
        raw = '''{"template-id":"cve-2024-1234","matched-at":"https://example.com/vuln","host":"example.com","info":{"name":"Test CVE","severity":"high","type":"http","description":"A test vulnerability","reference":["https://example.com"],"classification":{"cve-id":["CVE-2024-1234"],"cwe-id":["CWE-79"],"cvss-score":7.5},"tags":["cve"]}}\n'''
        items = scanner.parse_output(raw)
        assert len(items) == 1
        assert items[0]["severity"] == "high"
        assert items[0]["template_id"] == "cve-2024-1234"
        assert "CVE-2024-1234" in items[0]["cve_ids"]

    def test_severity_sorting(self):
        scanner = NucleiScanner()
        raw = '{"template-id":"low-vuln","host":"example.com","info":{"name":"Low Vuln","severity":"low","type":"http","description":"","classification":{}}}\n'
        raw += '{"template-id":"crit-vuln","host":"example.com","info":{"name":"Critical Vuln","severity":"critical","type":"http","description":"","classification":{}}}\n'
        items = scanner.parse_output(raw)
        assert len(items) == 2
        assert items[0]["severity"] == "critical"
        assert items[1]["severity"] == "low"

    def test_empty_output(self):
        scanner = NucleiScanner()
        items = scanner.parse_output("")
        assert len(items) == 0
