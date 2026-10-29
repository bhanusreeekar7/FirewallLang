"""Semantic Analyzer for FirewallLang.

Performs static verification, scoping checks, first-match policy shadowing detection,
contradiction analysis, and security sanity checks.
"""
from typing import List, Dict, Set, Optional, Tuple
from app.compiler.ast_nodes import FirewallNode, RuleNode
from app.compiler.diagnostics import Diagnostic

# Standard known network zones for academic/lab environments
STANDARD_ZONES: Dict[str, str] = {
    "web": "192.168.10.10",
    "db": "192.168.20.10",
    "app": "192.168.10.20",
    "lan": "192.168.1.0/24",
    "dmz": "172.16.0.0/24",
    "internal": "10.0.0.0/8",
    "external": "0.0.0.0/0",
    "mgmt": "192.168.100.0/24",
}

# High-risk / sensitive ports requiring scrutiny
HIGH_RISK_PORTS: Dict[int, str] = {
    21: "FTP (cleartext authentication)",
    23: "Telnet (unencrypted remote access)",
    25: "SMTP (open mail relay potential)",
    69: "TFTP (unauthenticated file transfer)",
    135: "RPC / NetBIOS",
    137: "NetBIOS Name Service",
    139: "NetBIOS Session Service",
    445: "SMB / Active Directory (WannaCry/EternalBlue vector)",
    1433: "Microsoft SQL Server",
    3306: "MySQL Database Server",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL Database Server",
    6379: "Redis (frequently unauthenticated)",
    27017: "MongoDB (default unauthenticated in legacy configs)",
}


class SemanticAnalyzer:
    def __init__(self, ast: FirewallNode):
        self.ast = ast
        self.diagnostics: List[Diagnostic] = []
        self.known_rule_names: Set[str] = set()

    def analyze(self) -> List[Diagnostic]:
        if not self.ast:
            return self.diagnostics

        valid_rules: List[RuleNode] = []

        # 1. Individual rule validation
        for rule in self.ast.rules:
            is_valid = self._validate_individual_rule(rule)
            if is_valid:
                valid_rules.append(rule)

        # 2. Inter-rule relationship validation (Shadowing, Redundancy, Contradiction)
        self._analyze_rule_interactions(valid_rules)

        return self.diagnostics

    def _validate_individual_rule(self, rule: RuleNode) -> bool:
        has_error = False

        # Check duplicate rule names
        if rule.name in self.known_rule_names:
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message=f"Duplicate rule name: '{rule.name}' is already defined",
                    line=rule.line,
                    column=rule.column,
                    rule_name=rule.name,
                    suggestion=f"Rename rule '{rule.name}' to a unique identifier.",
                )
            )
            has_error = True
        else:
            self.known_rule_names.add(rule.name)

        # Check rule completeness
        if not (rule.action and rule.protocol and rule.port and rule.source and rule.destination):
            # Incomplete rule diagnostics already reported by parser
            return False

        # Port range check
        if rule.port:
            if rule.port.value < 1 or rule.port.value > 65535:
                self.diagnostics.append(
                    Diagnostic(
                        severity="error",
                        message=f"Port {rule.port.value} is outside valid TCP/UDP range (1-65535)",
                        line=rule.port.line,
                        column=rule.port.column,
                        rule_name=rule.name,
                        suggestion="Specify a port number between 1 and 65535.",
                    )
                )
                has_error = True

        # Check zone mapping
        for addr_node, role in [(rule.source, "from"), (rule.destination, "to")]:
            if addr_node and not addr_node.is_any:
                zone_val = addr_node.value.lower()
                if zone_val not in STANDARD_ZONES:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="info",
                            message=f"Custom network zone '{addr_node.value}' used in '{role}' clause",
                            line=addr_node.line,
                            column=addr_node.column,
                            rule_name=rule.name,
                            suggestion=f"Zone will be mapped dynamically. Standard registered zones: {', '.join(STANDARD_ZONES.keys())}.",
                        )
                    )

        # Broad rule security check
        if rule.action and rule.action.value == "allow":
            if rule.source and rule.source.is_any:
                port_val = rule.port.value if rule.port else None
                if port_val in HIGH_RISK_PORTS:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="warning",
                            message=f"High-risk port {port_val} ({HIGH_RISK_PORTS[port_val]}) allowed from 'any' source",
                            line=rule.line,
                            column=rule.column,
                            rule_name=rule.name,
                            suggestion="Restrict source IP to a trusted management subnet instead of 'any'.",
                        )
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="info",
                            message=f"Permissive rule: Port {port_val} is open to all internet traffic ('from: any')",
                            line=rule.line,
                            column=rule.column,
                            rule_name=rule.name,
                            suggestion="Verify that public access is explicitly intended for this service.",
                        )
                    )

        return not has_error

    def _analyze_rule_interactions(self, rules: List[RuleNode]):
        """Evaluates first-match firewall semantics across rule order."""
        n = len(rules)
        for i in range(n):
            earlier = rules[i]
            for j in range(i + 1, n):
                later = rules[j]
                self._compare_rule_pair(earlier, later)

    def _compare_rule_pair(self, r1: RuleNode, r2: RuleNode):
        """Compares earlier rule r1 with later rule r2 under first-match semantics."""
        # 1. Protocol must match to overlap or shadow
        if r1.protocol.value != r2.protocol.value:
            return

        # 2. Port must match
        if r1.port.value != r2.port.value:
            return

        # Match dimensions:
        # Check source: r1 covers r2 if r1 is 'any' or r1.source == r2.source
        source_r1_covers_r2 = r1.source.is_any or (r1.source.value.lower() == r2.source.value.lower())
        source_r2_covers_r1 = r2.source.is_any or (r2.source.value.lower() == r1.source.value.lower())

        # Check destination: r1 covers r2 if r1 is 'any' or r1.destination == r2.destination
        dest_r1_covers_r2 = r1.destination.is_any or (r1.destination.value.lower() == r2.destination.value.lower())
        dest_r2_covers_r1 = r2.destination.is_any or (r2.destination.value.lower() == r1.destination.value.lower())

        r1_covers_r2 = source_r1_covers_r2 and dest_r1_covers_r2
        r2_covers_r1 = source_r2_covers_r1 and dest_r2_covers_r1

        same_conditions = (
            r1.source.value.lower() == r2.source.value.lower()
            and r1.destination.value.lower() == r2.destination.value.lower()
        )

        same_action = r1.action.value == r2.action.value

        if r1_covers_r2:
            # r1 completely covers all traffic that r2 matches!
            # Since r1 comes earlier in first-match order, r2 will NEVER match any new packet.
            if same_conditions and same_action:
                self.diagnostics.append(
                    Diagnostic(
                        severity="warning",
                        message=f"Redundant rule: '{r2.name}' is identical to earlier rule '{r1.name}'",
                        line=r2.line,
                        column=r2.column,
                        rule_name=r2.name,
                        suggestion=f"Remove duplicate rule '{r2.name}' to streamline policy evaluation.",
                    )
                )
            elif same_action:
                self.diagnostics.append(
                    Diagnostic(
                        severity="warning",
                        message=f"Shadowed rule: '{r2.name}' is completely shadowed by broader earlier rule '{r1.name}'",
                        line=r2.line,
                        column=r2.column,
                        rule_name=r2.name,
                        suggestion=f"Rule '{r1.name}' on line {r1.line} matches a superset of this traffic earlier. '{r2.name}' will never execute.",
                    )
                )
            else:
                # Contradictory action: r1 has allow and r2 has block (or vice-versa), but r1 matches first
                if same_conditions:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="error",
                            message=f"Contradictory rule: '{r2.name}' ({r2.action.value.upper()}) directly contradicts earlier rule '{r1.name}' ({r1.action.value.upper()}) for identical traffic",
                            line=r2.line,
                            column=r2.column,
                            rule_name=r2.name,
                            suggestion=f"Resolve conflicting action with rule '{r1.name}' (line {r1.line}) or remove the conflicting rule.",
                        )
                    )
                else:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="warning",
                            message=f"Contradictory shadowed rule: '{r2.name}' ({r2.action.value.upper()}) will be blocked/overridden by broader earlier rule '{r1.name}' ({r1.action.value.upper()})",
                            line=r2.line,
                            column=r2.column,
                            rule_name=r2.name,
                            suggestion=f"Move specific rule '{r2.name}' before broad rule '{r1.name}', or adjust scope.",
                        )
                    )
        elif not r1_covers_r2 and not r2_covers_r1:
            # Check for partial overlap between r1 and r2
            # E.g., r1: from lan, to any; r2: from any, to web
            # They overlap on packets from lan to web, but neither covers the other.
            # If actions are different, note partial overlap warning
            if not same_action:
                overlap_source = (r1.source.is_any or r2.source.is_any) or (r1.source.value.lower() == r2.source.value.lower())
                overlap_dest = (r1.destination.is_any or r2.destination.is_any) or (r1.destination.value.lower() == r2.destination.value.lower())
                if overlap_source and overlap_dest:
                    self.diagnostics.append(
                        Diagnostic(
                            severity="info",
                            message=f"Overlapping rules: '{r1.name}' ({r1.action.value.upper()}) and '{r2.name}' ({r2.action.value.upper()}) overlap partially but neither is completely shadowed",
                            line=r2.line,
                            column=r2.column,
                            rule_name=r2.name,
                            suggestion="Under first-match semantics, intersection traffic follows earlier rule '{r1.name}'. Verify intended precedence.",
                        )
                    )
