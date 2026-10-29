"""Typed Abstract Syntax Tree (AST) nodes for FirewallLang."""
from dataclasses import dataclass, field
from typing import List, Optional, Any, Dict


@dataclass
class ASTNode:
    line: int
    column: int

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError


@dataclass
class ActionNode(ASTNode):
    value: str  # "allow" | "block"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Action",
            "value": self.value,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class ProtocolNode(ASTNode):
    value: str  # "tcp" | "udp"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Protocol",
            "value": self.value,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class PortNode(ASTNode):
    value: int
    raw: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Port",
            "value": self.value,
            "raw": self.raw,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class AddressNode(ASTNode):
    value: str  # e.g., "any", "web", or identifier
    is_any: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Address",
            "value": self.value,
            "is_any": self.is_any,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class RuleNode(ASTNode):
    name: str
    action: Optional[ActionNode] = None
    protocol: Optional[ProtocolNode] = None
    port: Optional[PortNode] = None
    source: Optional[AddressNode] = None
    destination: Optional[AddressNode] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Rule",
            "name": self.name,
            "action": self.action.to_dict() if self.action else None,
            "protocol": self.protocol.to_dict() if self.protocol else None,
            "port": self.port.to_dict() if self.port else None,
            "source": self.source.to_dict() if self.source else None,
            "destination": self.destination.to_dict() if self.destination else None,
            "line": self.line,
            "column": self.column,
        }


@dataclass
class FirewallNode(ASTNode):
    name: str
    rules: List[RuleNode] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_type": "Firewall",
            "name": self.name,
            "rule_count": len(self.rules),
            "rules": [rule.to_dict() for rule in self.rules],
            "line": self.line,
            "column": self.column,
        }
