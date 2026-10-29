"""Formal Grammar and Documentation for FirewallLang DSL.

This module provides the formal EBNF definition of FirewallLang, suitable for
compiler viva explanations, reference documentation, and parser alignment.
"""

EBNF_GRAMMAR = r"""
Program             ::= FirewallDecl EOF

FirewallDecl        ::= "firewall" STRING_LITERAL "{" RuleList "}"

RuleList            ::= RuleDecl*

RuleDecl            ::= "rule" IDENTIFIER "{" FieldList "}"

FieldList           ::= (FieldDecl)*

FieldDecl           ::= ActionField
                      | ProtocolField
                      | PortField
                      | FromField
                      | ToField

ActionField         ::= "action" ":" ActionValue ";"
ActionValue         ::= "allow" | "block"

ProtocolField       ::= "protocol" ":" ProtocolValue ";"
ProtocolValue       ::= "tcp" | "udp"

PortField           ::= "port" ":" INTEGER_LITERAL ";"

FromField           ::= "from" ":" AddressValue ";"
ToField             ::= "to" ":" AddressValue ";"
AddressValue        ::= "any" | IDENTIFIER

Tokens:
  IDENTIFIER        ::= [a-zA-Z_][a-zA-Z0-9_]*
  STRING_LITERAL    ::= '"' [^"\n\r]* '"'
  INTEGER_LITERAL   ::= [0-9]+
  COMMENT           ::= ('#' | '//') [^\n\r]*
"""

GRAMMAR_SUMMARY = {
    "language": "FirewallLang",
    "version": "1.0.0",
    "parsing_technique": "Handwritten Recursive Descent (LL(1) with single-token lookahead)",
    "rules": {
        "FirewallDecl": "Defines the boundary and identifier for a firewall policy group.",
        "RuleDecl": "Encapsulates a single filtering rule with unique identifier and ordered priority.",
        "ActionField": "Specifies rule behavior: 'allow' (ACCEPT) or 'block' (DROP).",
        "ProtocolField": "L4 transport protocol: 'tcp' or 'udp'.",
        "PortField": "Target L4 destination port (valid range: 1-65535).",
        "FromField": "Traffic origin: 'any' (wildcard) or an identifier.",
        "ToField": "Traffic target: 'any' (wildcard) or a zone/host identifier (e.g. 'web').",
    },
}
