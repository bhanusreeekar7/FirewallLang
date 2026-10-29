"""Tests for Semantic Analysis: Shadowing, Overlaps, Contradictions, and Scoping."""
import pytest
from app.compiler.pipeline import CompilerPipeline


def test_duplicate_rule_names():
    source = """firewall "DupTest" {
    rule allow_web {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule allow_web {
        action: allow;
        protocol: tcp;
        port: 443;
        from: any;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    assert res.success is False
    assert any("Duplicate rule name: 'allow_web'" in d.message for d in res.diagnostics)


def test_invalid_port_range():
    source = """firewall "PortRange" {
    rule out_of_bounds {
        action: allow;
        protocol: tcp;
        port: 70000;
        from: any;
        to: any;
    }
}"""
    res = CompilerPipeline(source).run()
    assert res.success is False
    assert any("outside valid TCP/UDP range" in d.message for d in res.diagnostics)


def test_genuinely_shadowed_rule():
    source = """firewall "ShadowTest" {
    rule broad_allow {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: any;
    }
    rule specific_allow {
        action: allow;
        protocol: tcp;
        port: 80;
        from: lan;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    # broad_allow matches all sources and destinations for TCP 80, completely shadowing specific_allow
    assert any("Shadowed rule: 'specific_allow' is completely shadowed" in d.message for d in res.diagnostics)


def test_overlapping_rules_not_completely_shadowed():
    source = """firewall "OverlapTest" {
    rule lan_to_any {
        action: allow;
        protocol: tcp;
        port: 80;
        from: lan;
        to: any;
    }
    rule any_to_web {
        action: block;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    # Neither completely shadows the other:
    # Traffic from dmz to web matches any_to_web but not lan_to_any
    # Traffic from lan to db matches lan_to_any but not any_to_web
    shadowed_messages = [d.message for d in res.diagnostics if "Shadowed rule" in d.message]
    assert len(shadowed_messages) == 0

    overlap_messages = [d.message for d in res.diagnostics if "Overlapping rules" in d.message]
    assert len(overlap_messages) > 0


def test_contradictory_rules():
    source = """firewall "ConflictTest" {
    rule allow_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
    rule block_http {
        action: block;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
    res = CompilerPipeline(source).run()
    assert any("Contradictory rule" in d.message for d in res.diagnostics)


def test_high_risk_port_detection():
    source = """firewall "RiskTest" {
    rule allow_telnet {
        action: allow;
        protocol: tcp;
        port: 23;
        from: any;
        to: internal;
    }
}"""
    res = CompilerPipeline(source).run()
    assert any("High-risk port 23" in d.message for d in res.diagnostics)
