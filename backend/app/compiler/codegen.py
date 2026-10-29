"""Code Generator for FirewallLang.

Translates an AST into standard Linux iptables commands, modern Linux nftables scripts,
or JSON Intermediate Representation (IR).
Never executes commands automatically on the host.
"""
import json
from typing import List, Dict, Tuple, Optional, Any
from app.compiler.ast_nodes import FirewallNode, RuleNode
from app.compiler.semantic import STANDARD_ZONES
from app.compiler.diagnostics import Diagnostic


class CodeGenerator:
    def __init__(self, ast: FirewallNode):
        self.ast = ast
        self.diagnostics: List[Diagnostic] = []

    def generate(self, target: str = "iptables") -> Tuple[str, List[Dict[str, str]], List[Diagnostic]]:
        """Generates shell script and structured commands for the requested target engine."""
        if not self.ast:
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message="Codegen error: Cannot generate commands from empty AST",
                    line=1,
                    column=1,
                )
            )
            return "", [], self.diagnostics

        if target.lower() == "nftables":
            return self.generate_nftables()
        elif target.lower() == "json":
            return self.generate_json_ir()
        else:
            return self.generate_iptables()

    def generate_iptables(self) -> Tuple[str, List[Dict[str, str]], List[Diagnostic]]:
        """Generates classic Linux iptables shell script and structured command list."""
        lines: List[str] = []
        structured_commands: List[Dict[str, str]] = []

        # Standard baseline setup
        lines.append("# [Phase 1: Table Initialization & Default Policies]")
        lines.append("iptables -F INPUT")
        lines.append("iptables -P INPUT DROP\n")

        lines.append("# [Phase 2: Essential Stateful & Loopback Filtering]")
        lines.append("iptables -A INPUT -i lo -j ACCEPT -m comment --comment \"Allow loopback\"")
        lines.append("iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT -m comment --comment \"Stateful returns\"\n")

        lines.append("# [Phase 3: Compiled User Policy Rules]")

        for rule in self.ast.rules:
            cmd, comment = self._generate_rule_command(rule)
            if cmd:
                lines.append(f"# Rule: {rule.name} (Source Line: {rule.line})")
                lines.append(cmd + "\n")
                structured_commands.append({
                    "rule_name": rule.name,
                    "command": cmd,
                    "comment": comment,
                    "line": str(rule.line),
                })

        return "\n".join(lines), structured_commands, self.diagnostics

    def generate_nftables(self) -> Tuple[str, List[Dict[str, str]], List[Diagnostic]]:
        """Generates modern Linux nftables configuration script."""
        lines: List[str] = []
        structured_commands: List[Dict[str, str]] = []

        lines.append("#!/usr/sbin/nft -f")
        lines.append("# ================================================================")
        lines.append(f"# FirewallLang Compiled Ruleset — Target: Linux nftables")
        lines.append(f"# Policy: \"{self.ast.name}\" | Compiled Rules: {len(self.ast.rules)}")
        lines.append("# ================================================================")
        lines.append("flush ruleset\n")

        lines.append("table inet filter {")
        lines.append("    chain input {")
        lines.append("        type filter hook input priority 0; policy drop;\n")
        lines.append("        # Base security invariants")
        lines.append("        iif \"lo\" accept comment \"Allow loopback\"")
        lines.append("        ct state established,related accept comment \"Stateful return traffic\"\n")
        lines.append("        # Compiled policy rules")

        for rule in self.ast.rules:
            if not (rule.action and rule.protocol and rule.port and rule.source and rule.destination):
                continue

            proto = rule.protocol.value.lower()
            port = rule.port.value
            verdict = "accept" if rule.action.value.lower() == "allow" else "drop"

            parts = []
            if not rule.source.is_any:
                src_val = rule.source.value.lower()
                src_ip = STANDARD_ZONES.get(src_val, src_val)
                parts.append(f"ip saddr {src_ip}")

            if not rule.destination.is_any:
                dst_val = rule.destination.value.lower()
                dst_ip = STANDARD_ZONES.get(dst_val, dst_val)
                parts.append(f"ip daddr {dst_ip}")

            parts.append(f"{proto} dport {port}")
            parts.append(verdict)
            parts.append(f'comment "FWLang: {rule.name}"')

            rule_line = "        " + " ".join(parts)
            lines.append(rule_line)

            structured_commands.append({
                "rule_name": rule.name,
                "command": f"nft add rule inet filter input {' '.join(parts)}",
                "comment": f"{verdict.upper()} {proto}:{port}",
                "line": str(rule.line),
            })

        lines.append("    }")
        lines.append("}")

        return "\n".join(lines), structured_commands, self.diagnostics

    def generate_json_ir(self) -> Tuple[str, List[Dict[str, str]], List[Diagnostic]]:
        """Emits structured JSON Intermediate Representation (IR) for automation/SIEM."""
        ir: Dict[str, Any] = {
            "version": "1.0.0",
            "policy_name": self.ast.name,
            "default_policy": "DROP",
            "rules": [],
        }

        for rule in self.ast.rules:
            if not (rule.action and rule.protocol and rule.port and rule.source and rule.destination):
                continue

            src_val = rule.source.value.lower()
            dst_val = rule.destination.value.lower()

            ir["rules"].append({
                "name": rule.name,
                "line": rule.line,
                "action": rule.action.value.upper(),
                "protocol": rule.protocol.value.upper(),
                "destination_port": rule.port.value,
                "source": {
                    "raw": rule.source.value,
                    "is_any": rule.source.is_any,
                    "resolved_ip": "0.0.0.0/0" if rule.source.is_any else STANDARD_ZONES.get(src_val, src_val),
                },
                "destination": {
                    "raw": rule.destination.value,
                    "is_any": rule.destination.is_any,
                    "resolved_ip": "0.0.0.0/0" if rule.destination.is_any else STANDARD_ZONES.get(dst_val, dst_val),
                },
            })

        json_str = json.dumps(ir, indent=2)
        return json_str, [], self.diagnostics

    def _generate_rule_command(self, rule: RuleNode) -> Tuple[Optional[str], str]:
        # Validate node components
        if not (rule.action and rule.protocol and rule.port and rule.source and rule.destination):
            self.diagnostics.append(
                Diagnostic(
                    severity="error",
                    message=f"Codegen error: Rule '{rule.name}' has incomplete fields",
                    line=rule.line,
                    column=rule.column,
                    rule_name=rule.name,
                )
            )
            return None, ""

        parts = ["iptables -A INPUT"]

        # Protocol
        proto = rule.protocol.value.lower()
        parts.append(f"-p {proto}")

        # Destination Port
        port = rule.port.value
        parts.append(f"--dport {port}")

        # Source IP / Zone
        if not rule.source.is_any:
            src_val = rule.source.value.lower()
            src_ip = STANDARD_ZONES.get(src_val, src_val)
            parts.append(f"-s {src_ip}")

        # Destination IP / Zone
        if not rule.destination.is_any:
            dst_val = rule.destination.value.lower()
            dst_ip = STANDARD_ZONES.get(dst_val, dst_val)
            parts.append(f"-d {dst_ip}")

        # Action (allow -> ACCEPT, block -> DROP)
        action_map = {
            "allow": "ACCEPT",
            "block": "DROP",
        }
        target_action = action_map.get(rule.action.value.lower(), "DROP")
        parts.append(f"-j {target_action}")

        # Comment tag
        parts.append(f'-m comment --comment "FWLang: {rule.name}"')

        cmd = " ".join(parts)
        comment_desc = f"{rule.action.value.upper()} {proto.upper()}:{port} from {rule.source.value} to {rule.destination.value}"
        return cmd, comment_desc
