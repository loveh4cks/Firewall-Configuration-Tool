from abc import ABC, abstractmethod
from typing import List, Dict, Any, Tuple


class FirewallManager(ABC):
    """Abstract base class for firewall operations."""

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run
        self._log: List[str] = []

    def get_log(self) -> List[str]:
        """Return accumulated log messages."""
        return list(self._log)

    def clear_log(self):
        """Clear the log."""
        self._log.clear()

    @abstractmethod
    def add_rule(self, rule: Dict[str, Any]) -> None:
        """Add a firewall rule."""
        pass

    @abstractmethod
    def remove_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Remove a firewall rule by name. Returns (success, message)."""
        pass

    @abstractmethod
    def enable_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Enable a firewall rule. Returns (success, message)."""
        pass

    @abstractmethod
    def disable_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Disable a firewall rule. Returns (success, message)."""
        pass

    @abstractmethod
    def delete_rule(self, rule_name: str) -> Tuple[bool, str]:
        """Delete a firewall rule permanently. Returns (success, message)."""
        pass

    @abstractmethod
    def list_rules(self) -> List[Dict[str, Any]]:
        """List current firewall rules."""
        pass

    def apply_policy(self, rules: List[Dict[str, Any]]) -> None:
        """Apply a list of rules (policy)."""
        self._log.append(f"Applying {len(rules)} rules...")
        for rule in rules:
            self.add_rule(rule)
