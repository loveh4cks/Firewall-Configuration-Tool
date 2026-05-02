import subprocess
import json
from typing import List, Dict, Any, Tuple
from ..firewall_manager import FirewallManager


class WindowsFirewallManager(FirewallManager):
    """Windows implementation of FirewallManager using PowerShell."""

    def __init__(self, dry_run: bool = False):
        super().__init__(dry_run)

    def _execute_powershell(self, command: str) -> Tuple[bool, str]:
        """Execute a PowerShell command. Returns (success, output_or_error)."""
        if self.dry_run:
            msg = f"[DRY RUN] {command}"
            self._log.append(msg)
            return True, msg
        else:
            try:
                result = subprocess.run(
                    ["powershell", "-Command", command],
                    capture_output=True, text=True, timeout=120
                )
                if result.returncode != 0:
                    msg = f"[ERROR] {command}\n{result.stderr.strip()}"
                    self._log.append(msg)
                    return False, msg
                else:
                    msg = f"[SUCCESS] {command}"
                    self._log.append(msg)
                    return True, result.stdout.strip()
            except subprocess.TimeoutExpired:
                msg = f"[TIMEOUT] {command}"
                self._log.append(msg)
                return False, msg
            except Exception as e:
                msg = f"[FAILED] {command}: {e}"
                self._log.append(msg)
                return False, msg

    def add_rule(self, rule: Dict[str, Any]) -> None:
        name = rule.get('name', 'Unnamed Rule')
        direction = rule.get('direction', 'inbound').capitalize()
        action = rule.get('action', 'allow').capitalize()
        protocol = rule.get('protocol', 'TCP').upper()

        # Windows requires a specific protocol (TCP/UDP) when -LocalPort is used.
        has_port = 'port' in rule and str(rule['port']).strip()
        if has_port and protocol == 'ANY':
            protocol = 'TCP'
            self._log.append(f"[WARNING] Port specified with protocol=Any. Auto-defaulting to TCP for rule '{name}'.")

        cmd_parts = [
            "New-NetFirewallRule",
            f'-DisplayName "{name}"',
            f'-Direction {direction}',
            f'-Action {action}'
        ]

        if protocol != 'ANY':
            cmd_parts.append(f'-Protocol {protocol}')
        if has_port:
            cmd_parts.append(f'-LocalPort {rule["port"]}')
        if 'remote_ip' in rule and str(rule.get('remote_ip', '')).strip():
            cmd_parts.append(f'-RemoteAddress {rule["remote_ip"]}')

        command = " ".join(cmd_parts)
        self._execute_powershell(command)

    def remove_rule(self, rule_name: str) -> Tuple[bool, str]:
        command = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
        return self._execute_powershell(command)

    def enable_rule(self, rule_name: str) -> Tuple[bool, str]:
        command = f'Enable-NetFirewallRule -DisplayName "{rule_name}"'
        return self._execute_powershell(command)

    def disable_rule(self, rule_name: str) -> Tuple[bool, str]:
        command = f'Disable-NetFirewallRule -DisplayName "{rule_name}"'
        return self._execute_powershell(command)

    def delete_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Delete a firewall rule. Disables first if enabled, then removes."""
        # First disable it to be safe
        self.disable_rule(rule_name)
        # Then remove it
        return self.remove_rule(rule_name)

    def list_rules(self) -> List[Dict[str, Any]]:
        """Fetch all current firewall rules with protocol and port info."""
        command = (
            "$pfHash = @{}; "
            "Get-NetFirewallPortFilter | ForEach-Object { $pfHash[$_.InstanceID] = $_ }; "
            "Get-NetFirewallRule | ForEach-Object { "
            "  $pf = $pfHash[$_.Name]; "
            "  [PSCustomObject]@{ "
            "    DisplayName = $_.DisplayName; "
            "    Direction   = $_.Direction; "
            "    Action      = $_.Action; "
            "    Enabled     = $_.Enabled; "
            "    Protocol    = $(if($pf -and $pf.Protocol){ $pf.Protocol } else { 'Any' }); "
            "    LocalPort   = $(if($pf -and $pf.LocalPort){ $pf.LocalPort -join ',' } else { 'Any' }); "
            "  } "
            "} | ConvertTo-Json -Depth 3 -Compress"
        )
        success, output = self._execute_powershell(command)
        if not success or not output:
            return []

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            return []

        if isinstance(data, dict):
            data = [data]

        rules = []
        for item in data:
            direction_val = item.get("Direction", 1)
            if isinstance(direction_val, int):
                direction = "Inbound" if direction_val == 1 else "Outbound"
            else:
                direction = str(direction_val)

            action_val = item.get("Action", 2)
            if isinstance(action_val, int):
                action = "Allow" if action_val == 2 else "Block"
            else:
                action = str(action_val)

            enabled_val = item.get("Enabled", True)
            if isinstance(enabled_val, int):
                enabled = enabled_val == 1
            else:
                enabled = bool(enabled_val)

            protocol = item.get("Protocol", "Any")
            if protocol is None:
                protocol = "Any"

            local_port = item.get("LocalPort", "Any")
            if local_port is None:
                local_port = "Any"
            elif isinstance(local_port, list):
                local_port = ", ".join(str(p) for p in local_port)

            rules.append({
                "name": item.get("DisplayName", "Unknown"),
                "direction": direction,
                "action": action,
                "enabled": enabled,
                "protocol": str(protocol),
                "port": str(local_port)
            })

        return rules
