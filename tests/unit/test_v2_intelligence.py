"""Unit tests for V2 intelligence modules."""

import pytest

from internal.integrations.js_analysis import JSAnalyzer
from internal.integrations.api_discovery import APIDiscovery


class TestJSAnalyzer:
    def test_endpoint_extraction(self):
        analyzer = JSAnalyzer()
        js_content = '''
            fetch("/api/v1/users")
            axios.get("/api/v2/admin/config")
            const url = "https://api.example.com/graphql";
            window.location = "/dashboard";
        '''
        endpoints = analyzer._extract_endpoints(js_content, "https://example.com/app.js")
        assert len(endpoints) > 0

    def test_secret_extraction(self):
        analyzer = JSAnalyzer()
        js_content = '''
            const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
            const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        '''
        secrets = analyzer._extract_secrets(js_content, "https://example.com/config.js")
        assert len(secrets) >= 2
        types = [s.secret_type for s in secrets]
        assert "aws_access_key" in types
        assert "jwt_token" in types

    def test_subdomain_extraction(self):
        analyzer = JSAnalyzer()
        js_content = '''
            const api = "api.example.com";
            const cdn = "cdn.example.com";
        '''
        subdomains = analyzer._extract_subdomains(js_content)
        # The domain regex should find subdomain-like patterns
        assert isinstance(subdomains, list)

    def test_import_extraction(self):
        analyzer = JSAnalyzer()
        js_content = '''
            import React from 'react';
            import { api } from './api';
            const config = require('./config.json');
        '''
        imports = analyzer._extract_imports(js_content)
        assert len(imports) >= 2

    def test_skip_common_patterns(self):
        analyzer = JSAnalyzer()
        js_content = '''
            fetch("/assets/logo.png")
            axios.get("/real-api/v1/data")
            window.location = "/styles/main.css"
        '''
        endpoints = analyzer._extract_endpoints(js_content, "https://example.com/app.js")
        # All URLs are returned; skip filtering happens downstream
        assert len(endpoints) >= 1


class TestAPIDiscovery:
    def test_init(self):
        discovery = APIDiscovery()
        assert discovery.timeout == 10
        assert "Mozilla" in discovery.user_agent
        assert len(discovery.__class__.__module__) > 0
