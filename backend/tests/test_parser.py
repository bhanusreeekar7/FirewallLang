"""Tests for FirewallLang Parser and AST construction."""
import pytest
from app.compiler.lexer import Lexer
from app.compiler.parser import Parser
from app.compiler.ast_nodes import FirewallNode, RuleNode


def test_parser_valid_firewall():
    source = """firewall "CorporateDMZ" {
    rule allow_https {
        action: allow;
        protocol: tcp;
        port: 443;
        from: any;
        to: web;
    }
}"""
    lexer = Lexer(source)
    tokens, _ = lexer.tokenize()
    parser = Parser(tokens)
    ast, diags = parser.parse()

    assert ast is not None
    assert ast.name == "CorporateDMZ"
    assert len(ast.rules) == 1

    rule = ast.rules[0]
    assert rule.name == "allow_https"
    assert rule.action.value == "allow"
    assert rule.protocol.value == "tcp"
    assert rule.port.value == 443
    assert rule.source.is_any is True
    assert rule.destination.value == "web"
    assert rule.destination.is_any is False
    assert len(diags) == 0


def test_parser_missing_closing_brace():
    source = """firewall "Broken" {
    rule allow_dns {
        action: allow;
        protocol: udp;
        port: 53;
        from: any;
        to: internal;
"""
    lexer = Lexer(source)
    tokens, _ = lexer.tokenize()
    parser = Parser(tokens)
    ast, diags = parser.parse()

    assert any(d.severity == "error" and "Expected '}'" in d.message for d in diags)


def test_parser_missing_required_fields():
    source = """firewall "Incomplete" {
    rule incomplete_rule {
        action: allow;
        port: 80;
    }
}"""
    lexer = Lexer(source)
    tokens, _ = lexer.tokenize()
    parser = Parser(tokens)
    ast, diags = parser.parse()

    assert any("missing required field(s)" in d.message for d in diags)


def test_parser_invalid_port_syntax():
    source = """firewall "BadPort" {
    rule bad {
        action: allow;
        protocol: tcp;
        port: not_a_number;
        from: any;
        to: any;
    }
}"""
    lexer = Lexer(source)
    tokens, _ = lexer.tokenize()
    parser = Parser(tokens)
    ast, diags = parser.parse()

    assert any("Expected numeric port number" in d.message for d in diags)
