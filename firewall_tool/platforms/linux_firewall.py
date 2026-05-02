import subprocess
import re
from typing import List, Dict, Any, Tuple
from ..firewall_manager import FirewallManager


class LinuxFirewallManager(FirewallManager):
    """Linux implementation of FirewallManager using iptables.
    
    Notes:
    - iptables doesn't have named rules or enable/disable like Windows.
    - We use the 'comment' match extension to tag rules with names.
    - 'Disabling' a rule means deleting it but keeping it in our tracking.
    - Requires root/sudo privileges for all operations.
    """

    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)

    def _execute_command(self, command: List[str]) -> Tuple[bool, str]:
        """Execute a shell command. Returns (success, output_or_error)."""
        cmd_str = " ".join(command)
        if self.dry_run:
            msg = f"[DRY RUN] {cmd_str}"
            self._log.append(msg)
            return True, msg
        else:
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True, timeout=30
                )
                if result.returncode != 0:
                    msg = f"[ERROR] {cmd_str}\n{result.stderr.strip()}"
                    self._log.append(msg)
                    return False, msg
                else:
                    msg = f"[SUCCESS] {cmd_str}"
                    self._log.append(msg)
                    return True, result.stdout.strip()
            except subprocess.TimeoutExpired:
                msg = f"[TIMEOUT] {cmd_str}"
                self._log.append(msg)
                return False, msg
            except FileNotFoundError:
                msg = f"[FAILED] {cmd_str}: iptables not found. Install it or run on Linux."
                self._log.append(msg)
                return False, msg
            except Exception as e:
                msg = f"[FAILED] {cmd_str}: {e}"
                self._log.append(msg)
                return False, msg

    def add_rule(self, rule: Dict[str, Any]) -> None:
        """Add an iptables rule with a comment tag for identification."""
        name = rule.get('name', 'Unnamed Rule')
        chain = "INPUT" if rule.get('direction', 'inbound').lower() == "inbound" else "OUTPUT"
        action_map = {"allow": "ACCEPT", "block": "DROP"}
        action = action_map.get(rule.get('action', 'allow').lower(), "ACCEPT")

        cmd = ["sudo", "iptables", "-A", chain]

        protocol = rule.get('protocol', 'tcp').lower()
        has_port = 'port' in rule and str(rule.get('port', '')).strip()

        # If port is specified but protocol is 'any', default to tcp
        if has_port and protocol == 'any':
            protocol = 'tcp'
            self._log.append(f"[WARNING] Port specified with protocol=any. Auto-defaulting to tcp for rule '{name}'.")

        if protocol != 'any':
            cmd.extend(["-p", protocol])

        if has_port:
            cmd.extend(["--dport", str(rule['port'])])

        if 'remote_ip' in rule and str(rule.get('remote_ip', '')).strip():
            cmd.extend(["-s", rule['remote_ip']])

        cmd.extend(["-j", action])

        # Add comment for identification
        cmd.extend(["-m", "comment", "--comment", name])

        self._execute_command(cmd)

    def remove_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Remove all iptables rules matching the given comment name."""
        # First find the rule numbers, then delete them (in reverse order)
        success = True
        last_msg = ""

        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            # Get rules with line numbers
            ok, output = self._execute_command(
                ["sudo", "iptables", "-L", chain, "--line-numbers", "-n"]
            )
            if not ok:
                continue

            # Parse output to find lines with the rule name in comment
            lines_to_delete = []
            for line in output.split("\n"):
                if rule_name in line:
                    # Extract rule number (first column)
                    match = re.match(r'^(\d+)', line.strip())
                    if match:
                        lines_to_delete.append(int(match.group(1)))

            # Delete in reverse order so line numbers don't shift
            for line_num in sorted(lines_to_delete, reverse=True):
                ok, msg = self._execute_command(
                    ["sudo", "iptables", "-D", chain, str(line_num)]
                )
                if not ok:
                    success = False
                last_msg = msg

        if success and not last_msg:
            last_msg = f"[SUCCESS] Removed rules matching '{rule_name}'"
        return success, last_msg

    def enable_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Enable (re-add) a rule. 
        
        iptables doesn't have enable/disable — this is a no-op message.
        The user should re-add the rule from their policy list.
        """
        msg = (f"[WARNING] iptables doesn't support enable/disable. "
               f"To re-enable '{rule_name}', re-apply it from your policy list.")
        self._log.append(msg)
        return False, msg

    def disable_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Disable (remove) a rule from iptables.
        
        Since iptables doesn't have enable/disable, disabling = removing the rule.
        """
        return self.remove_rule(rule_name)

    def delete_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Delete a rule permanently from iptables."""
        return self.remove_rule(rule_name)

    def list_rules(self) -> List[Dict[str, Any]]:
        """Fetch all current iptables rules with parsed details."""
        rules = []

        for chain, direction in [("INPUT", "Inbound"), ("OUTPUT", "Outbound"), ("FORWARD", "Forward")]:
            ok, output = self._execute_command(
                ["sudo", "iptables", "-L", chain, "-n", "-v", "--line-numbers"]
            )
            if not ok or not output:
                continue

            lines = output.strip().split("\n")
            # Skip header lines (first 2 lines are chain info and column headers)
            if len(lines) < 3:
                continue

            for line in lines[2:]:
                parsed = self._parse_iptables_line(line, direction)
                if parsed:
                    rules.append(parsed)

        return rules

    def _parse_iptables_line(self, line: str, direction: str) -> Dict[str, Any]:
        """Parse a single iptables -L -n -v --line-numbers output line."""
        # Format: num  pkts bytes target  prot opt in   out  source    destination  [extras]
        # Example: 1    123  456K ACCEPT  tcp  --  *    *    0.0.0.0/0 0.0.0.0/0   tcp dpt:80 /* Allow Web */
        line = line.strip()
        if not line:
            return None

        parts = line.split()
        if len(parts) < 9:
            return None

        try:
            # rule_num = parts[0]  # line number
            # pkts = parts[1]
            # bytes_col = parts[2]
            target = parts[3]    # ACCEPT, DROP, REJECT, etc.
            protocol = parts[4]  # tcp, udp, all, etc.
            # opt = parts[5]
            # in_iface = parts[6]
            # out_iface = parts[7]
            source = parts[8]    # source IP
            # parts[9] is destination IP — not used in our rule dict but parsed for completeness
        except (IndexError, ValueError):
            return None

        # Map target to action
        action_map = {"ACCEPT": "Allow", "DROP": "Block", "REJECT": "Block"}
        action = action_map.get(target, target)

        # Extract port from extras (e.g., "tcp dpt:80")
        port = "Any"
        rest = " ".join(parts[10:]) if len(parts) > 10 else ""
        port_match = re.search(r'dpt:(\d+)', rest)
        if port_match:
            port = port_match.group(1)
        port_range_match = re.search(r'dpts:(\d+:\d+)', rest)
        if port_range_match:
            port = port_range_match.group(1).replace(":", "-")

        # Extract comment (rule name)
        name = "iptables rule"
        comment_match = re.search(r'/\*\s*(.+?)\s*\*/', rest)
        if comment_match:
            name = comment_match.group(1)
        else:
            # Generate a descriptive name
            name = f"{direction} {protocol.upper()} {action} port:{port}"

        # Remote IP
        remote_ip = source if source != "0.0.0.0/0" else "Any"

        # Protocol display
        proto_display = protocol.upper() if protocol != "all" else "Any"

        return {
            "name": name,
            "direction": direction,
            "action": action,
            "enabled": True,  # All listed rules in iptables are active
            "protocol": proto_display,
            "port": port,
            "remote_ip": remote_ip
        }
