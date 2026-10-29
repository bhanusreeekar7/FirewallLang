"""Token definitions for FirewallLang lexer."""
from enum import Enum, auto
from dataclasses import dataclass
from typing import Any


class TokenType(str, Enum):
    # Keywords
    FIREWALL = "FIREWALL"
    RULE = "RULE"
    ACTION = "ACTION"
    PROTOCOL = "PROTOCOL"
    PORT = "PORT"
    FROM = "FROM"
    TO = "TO"
    
    # Values / Enum literals
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    TCP = "TCP"
    UDP = "UDP"
    ANY = "ANY"

    # Literals
    IDENTIFIER = "IDENTIFIER"
    STRING_LITERAL = "STRING_LITERAL"
    INTEGER_LITERAL = "INTEGER_LITERAL"

    # Delimiters and Punctuation
    LBRACE = "LBRACE"        # {
    RBRACE = "RBRACE"        # }
    COLON = "COLON"          # :
    SEMICOLON = "SEMICOLON"  # ;

    # Comments and Special
    COMMENT = "COMMENT"
    EOF = "EOF"
    UNKNOWN = "UNKNOWN"


KEYWORDS = {
    "firewall": TokenType.FIREWALL,
    "rule": TokenType.RULE,
    "action": TokenType.ACTION,
    "protocol": TokenType.PROTOCOL,
    "port": TokenType.PORT,
    "from": TokenType.FROM,
    "to": TokenType.TO,
    "allow": TokenType.ALLOW,
    "block": TokenType.BLOCK,
    "tcp": TokenType.TCP,
    "udp": TokenType.UDP,
    "any": TokenType.ANY,
}


@dataclass
class Token:
    type: TokenType
    value: str
    line: int
    column: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "line": self.line,
            "column": self.column,
        }
