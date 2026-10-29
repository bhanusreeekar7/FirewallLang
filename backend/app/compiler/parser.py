"""Handwritten Recursive-Descent Parser for FirewallLang."""
from typing import List, Optional, Tuple, Set
from app.compiler.tokens import Token, TokenType
from app.compiler.diagnostics import Diagnostic
from app.compiler.ast_nodes import (
    FirewallNode,
    RuleNode,
    ActionNode,
    ProtocolNode,
    PortNode,
    AddressNode,
)


class Parser:
    def __init__(self, tokens: List[Token]):
        # Filter out comments for parsing
        self.tokens: List[Token] = [t for t in tokens if t.type != TokenType.COMMENT]
        self.pos = 0
        self.diagnostics: List[Diagnostic] = []

    def _peek(self, offset: int = 0) -> Token:
        idx = self.pos + offset
        if idx >= len(self.tokens):
            return self.tokens[-1] if self.tokens else Token(TokenType.EOF, "", 1, 1)
        return self.tokens[idx]

    def _check(self, token_type: TokenType) -> bool:
        return self._peek().type == token_type

    def _advance(self) -> Token:
        tok = self._peek()
        if self.pos < len(self.tokens):
            self.pos += 1
        return tok

    def _consume(
        self,
        token_type: TokenType,
        error_message: str,
        suggestion: Optional[str] = None,
        rule_name: Optional[str] = None,
    ) -> Optional[Token]:
        tok = self._peek()
        if tok.type == token_type:
            return self._advance()

        self.diagnostics.append(
            Diagnostic(
                severity="error",
                message=f"Syntax error: {error_message} (found '{tok.value or tok.type.value}')",
                line=tok.line,
                column=tok.column,
                rule_name=rule_name,
                suggestion=suggestion,
            )
        )
        return None

    def _synchronize_rule(self):
        """Skip tokens until the next rule or closing brace of firewall block."""
        while not self._check(TokenType.EOF):
            tok = self._peek()
            if tok.type in (TokenType.RULE, TokenType.RBRACE):
                return
            self._advance()

    def parse(self) -> Tuple[Optional[FirewallNode], List[Diagnostic]]:
        """Parses the full token stream into a FirewallNode AST."""
        if self._peek().type == TokenType.EOF:
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message="Syntax error: Source file is empty",
                    line=1,
                    column=1,
                    suggestion="Add a firewall definition, e.g.: firewall \"MyFirewall\" { ... }",
                )
            )
            return None, self.diagnostics

        firewall_node = self._parse_firewall()

        # Check for unparsed trailing tokens
        if not self._check(TokenType.EOF) and firewall_node:
            trailing = self._peek()
            self.diagnostics.append(
                Diagnostic(
                    severity="warning",
                    message=f"Syntax warning: Unexpected token '{trailing.value}' after firewall block",
                    line=trailing.line,
                    column=trailing.column,
                    suggestion="Ensure there is only one top-level firewall block per file.",
                )
            )

        return firewall_node, self.diagnostics

    def _parse_firewall(self) -> Optional[FirewallNode]:
        fw_token = self._consume(
            TokenType.FIREWALL,
            "Expected 'firewall' keyword at beginning of program",
            suggestion="Start with: firewall \"<name>\" { ... }",
        )
        if not fw_token:
            return None

        name_token = self._consume(
            TokenType.STRING_LITERAL,
            "Expected string literal for firewall name",
            suggestion="Specify firewall name enclosed in double-quotes, e.g., firewall \"CorporateBorder\" {",
        )
        name = name_token.value if name_token else "UnnamedFirewall"

        lbrace = self._consume(
            TokenType.LBRACE,
            "Expected '{' after firewall name",
            suggestion="Add opening curly brace '{' after firewall name.",
        )
        if not lbrace:
            return None

        rules: List[RuleNode] = []
        while not self._check(TokenType.RBRACE) and not self._check(TokenType.EOF):
            if self._check(TokenType.RULE):
                rule = self._parse_rule()
                if rule:
                    rules.append(rule)
            else:
                tok = self._peek()
                self.diagnostics.append(
                    Diagnostic(
                        severity="error",
                        message=f"Syntax error: Expected 'rule' definition inside firewall, got '{tok.value}'",
                        line=tok.line,
                        column=tok.column,
                        suggestion="Define rules inside firewall block using: rule <rule_name> { ... }",
                    )
                )
                self._synchronize_rule()

        self._consume(
            TokenType.RBRACE,
            "Expected '}' to close firewall block",
            suggestion="Add closing curly brace '}' at end of firewall block.",
        )

        return FirewallNode(
            name=name,
            rules=rules,
            line=fw_token.line,
            column=fw_token.column,
        )

    def _parse_rule(self) -> Optional[RuleNode]:
        rule_kw = self._consume(TokenType.RULE, "Expected 'rule' keyword")
        if not rule_kw:
            return None

        name_tok = self._consume(
            TokenType.IDENTIFIER,
            "Expected identifier for rule name",
            suggestion="Use an identifier composed of letters, digits, and underscores (e.g. allow_http).",
        )
        rule_name = name_tok.value if name_tok else "unnamed_rule"

        lbrace = self._consume(
            TokenType.LBRACE,
            f"Expected '{{' after rule name '{rule_name}'",
            rule_name=rule_name,
            suggestion="Add '{' to open the rule body.",
        )
        if not lbrace:
            self._synchronize_rule()
            return None

        action: Optional[ActionNode] = None
        protocol: Optional[ProtocolNode] = None
        port: Optional[PortNode] = None
        source: Optional[AddressNode] = None
        destination: Optional[AddressNode] = None
        fields_seen: Set[str] = set()

        while not self._check(TokenType.RBRACE) and not self._check(TokenType.EOF):
            field_tok = self._peek()

            if field_tok.type == TokenType.ACTION:
                self._advance()
                if "action" in fields_seen:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message="Duplicate 'action' field in rule",
                            line=field_tok.line,
                            column=field_tok.column,
                            rule_name=rule_name,
                            suggestion="Each rule may only specify one 'action' field.",
                        )
                    )
                fields_seen.add("action")
                self._consume(TokenType.COLON, "Expected ':' after 'action'", rule_name=rule_name)
                val_tok = self._peek()
                if val_tok.type in (TokenType.ALLOW, TokenType.BLOCK):
                    self._advance()
                    action = ActionNode(
                        value=val_tok.value.lower(),
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Invalid action value '{val_tok.value}'. Must be 'allow' or 'block'",
                            line=val_tok.line,
                            column=val_tok.column,
                            rule_name=rule_name,
                            suggestion="Use 'action: allow;' or 'action: block;'.",
                        )
                    )
                    self._advance()
                self._consume(TokenType.SEMICOLON, "Expected ';' after action value", rule_name=rule_name)

            elif field_tok.type == TokenType.PROTOCOL:
                self._advance()
                if "protocol" in fields_seen:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message="Duplicate 'protocol' field in rule",
                            line=field_tok.line,
                            column=field_tok.column,
                            rule_name=rule_name,
                        )
                    )
                fields_seen.add("protocol")
                self._consume(TokenType.COLON, "Expected ':' after 'protocol'", rule_name=rule_name)
                val_tok = self._peek()
                if val_tok.type in (TokenType.TCP, TokenType.UDP):
                    self._advance()
                    protocol = ProtocolNode(
                        value=val_tok.value.lower(),
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Invalid protocol '{val_tok.value}'. Must be 'tcp' or 'udp'",
                            line=val_tok.line,
                            column=val_tok.column,
                            rule_name=rule_name,
                            suggestion="Use 'protocol: tcp;' or 'protocol: udp;'.",
                        )
                    )
                    self._advance()
                self._consume(TokenType.SEMICOLON, "Expected ';' after protocol value", rule_name=rule_name)

            elif field_tok.type == TokenType.PORT:
                self._advance()
                if "port" in fields_seen:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message="Duplicate 'port' field in rule",
                            line=field_tok.line,
                            column=field_tok.column,
                            rule_name=rule_name,
                        )
                    )
                fields_seen.add("port")
                self._consume(TokenType.COLON, "Expected ':' after 'port'", rule_name=rule_name)
                val_tok = self._peek()
                if val_tok.type == TokenType.INTEGER_LITERAL:
                    self._advance()
                    try:
                        p_val = int(val_tok.value)
                        port = PortNode(
                            value=p_val,
                            raw=val_tok.value,
                            line=val_tok.line,
                            column=val_tok.column,
                        )
                    except ValueError:
                        self.diagnostics.append(
                            Diagnostic(
                                severity="error",
                                message=f"Invalid port number '{val_tok.value}'",
                                line=val_tok.line,
                                column=val_tok.column,
                                rule_name=rule_name,
                            )
                        )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Expected numeric port number, got '{val_tok.value}'",
                            line=val_tok.line,
                            column=val_tok.column,
                            rule_name=rule_name,
                            suggestion="Specify an integer port between 1 and 65535.",
                        )
                    )
                    self._advance()
                self._consume(TokenType.SEMICOLON, "Expected ';' after port value", rule_name=rule_name)

            elif field_tok.type == TokenType.FROM:
                self._advance()
                if "from" in fields_seen:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message="Duplicate 'from' field in rule",
                            line=field_tok.line,
                            column=field_tok.column,
                            rule_name=rule_name,
                        )
                    )
                fields_seen.add("from")
                self._consume(TokenType.COLON, "Expected ':' after 'from'", rule_name=rule_name)
                val_tok = self._peek()
                if val_tok.type == TokenType.ANY:
                    self._advance()
                    source = AddressNode(
                        value="any",
                        is_any=True,
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                elif val_tok.type == TokenType.IDENTIFIER:
                    self._advance()
                    source = AddressNode(
                        value=val_tok.value,
                        is_any=False,
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Expected 'any' or identifier for source address, got '{val_tok.value}'",
                            line=val_tok.line,
                            column=val_tok.column,
                            rule_name=rule_name,
                            suggestion="Use 'from: any;' or an identifier like 'from: internal_net;'.",
                        )
                    )
                    self._advance()
                self._consume(TokenType.SEMICOLON, "Expected ';' after source value", rule_name=rule_name)

            elif field_tok.type == TokenType.TO:
                self._advance()
                if "to" in fields_seen:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message="Duplicate 'to' field in rule",
                            line=field_tok.line,
                            column=field_tok.column,
                            rule_name=rule_name,
                        )
                    )
                fields_seen.add("to")
                self._consume(TokenType.COLON, "Expected ':' after 'to'", rule_name=rule_name)
                val_tok = self._peek()
                if val_tok.type == TokenType.ANY:
                    self._advance()
                    destination = AddressNode(
                        value="any",
                        is_any=True,
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                elif val_tok.type == TokenType.IDENTIFIER:
                    self._advance()
                    destination = AddressNode(
                        value=val_tok.value,
                        is_any=False,
                        line=val_tok.line,
                        column=val_tok.column,
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Expected 'any' or identifier for destination address, got '{val_tok.value}'",
                            line=val_tok.line,
                            column=val_tok.column,
                            rule_name=rule_name,
                            suggestion="Use 'to: any;' or an identifier like 'to: web;'.",
                        )
                    )
                    self._advance()
                self._consume(TokenType.SEMICOLON, "Expected ';' after destination value", rule_name=rule_name)

            else:
                self.diagnostics.append(
                    Diagnostic(
                        severity="error",
                        message=f"Unknown or unexpected field '{field_tok.value}' inside rule '{rule_name}'",
                        line=field_tok.line,
                        column=field_tok.column,
                        rule_name=rule_name,
                        suggestion="Valid rule fields are: action, protocol, port, from, to.",
                    )
                )
                self._advance()

        self._consume(TokenType.RBRACE, f"Expected '}}' to close rule '{rule_name}'", rule_name=rule_name)

        # Validate mandatory fields
        required_fields = ["action", "protocol", "port", "from", "to"]
        missing = [f for f in required_fields if f not in fields_seen]
        if missing:
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message=f"Rule '{rule_name}' is missing required field(s): {', '.join(missing)}",
                    line=rule_kw.line,
                    column=rule_kw.column,
                    rule_name=rule_name,
                    suggestion=f"Provide definitions for {', '.join(missing)} in rule body.",
                )
            )

        return RuleNode(
            name=rule_name,
            action=action,
            protocol=protocol,
            port=port,
            source=source,
            destination=destination,
            line=rule_kw.line,
            column=rule_kw.column,
        )
