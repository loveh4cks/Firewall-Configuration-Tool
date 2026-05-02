# Note: Imports here might fail if dependencies (like pythonnet) aren't installed on the system,
# but for this structure it's good practice. We'll wrap in try-except if strictness is needed, 
# but for now we'll just expose them.

try:
    from .windows_firewall import WindowsFirewallManager
except ImportError:
    WindowsFirewallManager = None

try:
    from .linux_firewall import LinuxFirewallManager
except ImportError:
    LinuxFirewallManager = None

__all__ = ['WindowsFirewallManager', 'LinuxFirewallManager']
