"""Tests for FirewallLang Lexer."""
import pytest
from app.compiler.lexer import Lexer
from app.compiler.tokens import TokenType


def test_lexer_valid_tokens():
    source = """firewall "WebServer" {
    # Test comment
    rule allow_http {
        action: allow;
        protocol: tcp;
        port: 80;
        from: any;
        to: web;
    }
}"""
    lexer = Lexer(source)
    tokens, diags = lexer.tokenize()

    assert len(diags) == 0
    token_types = [t.type for t in tokens]

    assert TokenType.FIREWALL in token_types
    assert TokenType.STRING_LITERAL in token_types
    assert TokenType.COMMENT in token_types
    assert TokenType.RULE in token_types
    assert TokenType.IDENTIFIER in token_types
    assert TokenType.ACTION in token_types
    assert TokenType.ALLOW in token_types
    assert TokenType.PROTOCOL in token_types
    assert TokenType.TCP in token_types
    assert TokenType.PORT in token_types
    assert TokenType.INTEGER_LITERAL in token_types
    assert TokenType.FROM in token_types
    assert TokenType.ANY in token_types
    assert TokenType.TO in token_types
    assert TokenType.EOF in token_types


def test_lexer_positions_and_newlines():
    source = "firewall\n\"Prod\"\n{\n}"
    lexer = Lexer(source)
    tokens, diags = lexer.tokenize()

    assert tokens[0].type == TokenType.FIREWALL
    assert tokens[0].line == 1
    assert tokens[0].column == 1

    assert tokens[1].type == TokenType.STRING_LITERAL
    assert tokens[1].line == 2
    assert tokens[1].column == 1
    assert tokens[1].value == "Prod"

    assert tokens[2].type == TokenType.LBRACE
    assert tokens[2].line == 3
    assert tokens[2].column == 1


def test_lexer_invalid_characters():
    source = "firewall @$#% \"Test\" {}"
    lexer = Lexer(source)
    tokens, diags = lexer.tokenize()

    # Errors should be reported for '@' and '$'
    assert any(d.severity == "error" and "@" in d.message for d in diags)
    assert any(d.severity == "error" and "$" in d.message for d in diags)


def test_lexer_unterminated_string():
    source = 'firewall "Unterminated'
    lexer = Lexer(source)
    tokens, diags = lexer.tokenize()

    assert any("Unterminated string literal" in d.message for d in diags)
