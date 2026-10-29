"""Handwritten Lexer for FirewallLang."""
from typing import List, Tuple
from app.compiler.tokens import Token, TokenType, KEYWORDS
from app.compiler.diagnostics import Diagnostic


class Lexer:
    def __init__(self, source: str):
        self.source = source
        self.length = len(source)
        self.pos = 0
        self.line = 1
        self.column = 1
        self.diagnostics: List[Diagnostic] = []

    def _peek(self, offset: int = 0) -> str:
        idx = self.pos + offset
        if idx >= self.length:
            return ""
        return self.source[idx]

    def _advance(self) -> str:
        if self.pos >= self.length:
            return ""
        ch = self.source[self.pos]
        self.pos += 1
        if ch == "\n":
            self.line += 1
            self.column = 1
        else:
            self.column += 1
        return ch

    def tokenize(self) -> Tuple[List[Token], List[Diagnostic]]:
        tokens: List[Token] = []

        while self.pos < self.length:
            ch = self._peek()

            # Skip whitespace
            if ch in (" ", "\t", "\r", "\n"):
                self._advance()
                continue

            # Comments: '#' or '//'
            if ch == "#" or (ch == "/" and self._peek(1) == "/"):
                start_line = self.line
                start_col = self.column
                comment_chars = []
                if ch == "/":
                    self._advance()
                    self._advance()
                else:
                    self._advance()

                while self.pos < self.length and self._peek() not in ("\n", "\r"):
                    comment_chars.append(self._advance())
                tokens.append(
                    Token(
                        type=TokenType.COMMENT,
                        value="".join(comment_chars).strip(),
                        line=start_line,
                        column=start_col,
                    )
                )
                continue

            # Delimiters
            if ch == "{":
                tokens.append(Token(TokenType.LBRACE, "{", self.line, self.column))
                self._advance()
                continue
            if ch == "}":
                tokens.append(Token(TokenType.RBRACE, "}", self.line, self.column))
                self._advance()
                continue
            if ch == ":":
                tokens.append(Token(TokenType.COLON, ":", self.line, self.column))
                self._advance()
                continue
            if ch == ";":
                tokens.append(Token(TokenType.SEMICOLON, ";", self.line, self.column))
                self._advance()
                continue

            # String literals
            if ch == '"':
                tokens.append(self._lex_string())
                continue

            # Integer literals
            if ch.isdigit():
                tokens.append(self._lex_number())
                continue

            # Identifiers and keywords: [a-zA-Z_][a-zA-Z0-9_]*
            if ch.isalpha() or ch == "_":
                tokens.append(self._lex_identifier_or_keyword())
                continue

            # Unknown character
            err_line = self.line
            err_col = self.column
            bad_char = self._advance()
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message=f"Lexical error: Unexpected character '{bad_char}'",
                    line=err_line,
                    column=err_col,
                    suggestion="Remove or replace the invalid character.",
                )
            )
            tokens.append(
                Token(
                    type=TokenType.UNKNOWN,
                    value=bad_char,
                    line=err_line,
                    column=err_col,
                )
            )

        tokens.append(Token(TokenType.EOF, "", self.line, self.column))
        return tokens, self.diagnostics

    def _lex_string(self) -> Token:
        start_line = self.line
        start_col = self.column
        self._advance()  # consume opening quote
        chars = []

        while self.pos < self.length:
            ch = self._peek()
            if ch == '"':
                self._advance()  # consume closing quote
                return Token(
                    type=TokenType.STRING_LITERAL,
                    value="".join(chars),
                    line=start_line,
                    column=start_col,
                )
            if ch in ("\n", "\r"):
                # Multi-line strings not allowed without escape
                self.diagnostics.append(
                    Diagnostic(
                        severity="error",
                        message="Lexical error: Unterminated string literal before newline",
                        line=start_line,
                        column=start_col,
                        suggestion="Add a closing double-quote before the newline.",
                    )
                )
                return Token(
                    type=TokenType.STRING_LITERAL,
                    value="".join(chars),
                    line=start_line,
                    column=start_col,
                )
            if ch == "\\":
                self._advance()
                escaped = self._advance()
                if escaped == "n":
                    chars.append("\n")
                elif escaped == "t":
                    chars.append("\t")
                elif escaped == '"':
                    chars.append('"')
                elif escaped == "\\":
                    chars.append("\\")
                else:
                    chars.append(escaped)
            else:
                chars.append(self._advance())

        self.diagnostics.append(
            Diagnostic(
                severity="error",
                message="Lexical error: Unterminated string literal at end of file",
                line=start_line,
                column=start_col,
                suggestion="Add a closing double-quote '\"'.",
            )
        )
        return Token(
            type=TokenType.STRING_LITERAL,
            value="".join(chars),
            line=start_line,
            column=start_col,
        )

    def _lex_number(self) -> Token:
        start_line = self.line
        start_col = self.column
        chars = []

        while self.pos < self.length and self._peek().isdigit():
            chars.append(self._advance())

        num_str = "".join(chars)
        return Token(
            type=TokenType.INTEGER_LITERAL,
            value=num_str,
            line=start_line,
            column=start_col,
        )

    def _lex_identifier_or_keyword(self) -> Token:
        start_line = self.line
        start_col = self.column
        chars = []

        while self.pos < self.length and (
            self._peek().isalnum() or self._peek() == "_"
        ):
            chars.append(self._advance())

        ident = "".join(chars)
        lower_ident = ident.lower()

        # Check keyword map
        if lower_ident in KEYWORDS:
            token_type = KEYWORDS[lower_ident]
            return Token(
                type=token_type,
                value=ident,
                line=start_line,
                column=start_col,
            )

        return Token(
            type=TokenType.IDENTIFIER,
            value=ident,
            line=start_line,
            column=start_col,
        )
