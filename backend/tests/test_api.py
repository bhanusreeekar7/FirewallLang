"""Tests for FastAPI HTTP endpoints."""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_api_lex():
    res = client.post("/api/v1/lex", json={"source": "firewall \"Web\" {}"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert len(data["tokens"]) > 0


def test_api_parse():
    res = client.post("/api/v1/parse", json={"source": "firewall \"Web\" {}"})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["ast"]["name"] == "Web"


def test_api_analyze_valid():
    source = """firewall "Production" {
    rule allow_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
    res = client.post("/api/v1/analyze", json={"source": source})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["has_errors"] is False
    assert len(data["tokens"]) > 0
    assert data["ast"] is not None
    assert data["generated_code"] is not None
    assert "risk" in data
    assert 0 <= data["risk"]["score"] <= 100


def test_api_analyze_invalid_syntax():
    source = "firewall \"Broken\" { rule invalid {"
    res = client.post("/api/v1/analyze", json={"source": source})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is False
    assert data["has_errors"] is True
    assert len(data["diagnostics"]) > 0
    assert data["generated_code"] is None


def test_api_generate_endpoint():
    source = """firewall "AppCluster" {
    rule allow_ssh {
        action: allow;
        protocol: tcp;
        port: 22;
        from: mgmt;
        to: internal;
    }
}"""
    res = client.post("/api/v1/generate", json={"source": source})
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert "iptables -A INPUT -p tcp --dport 22" in data["generated_code"]
