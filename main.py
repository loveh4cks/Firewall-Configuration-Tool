import argparse
import sys
import platform
import os

# Add current directory to path so imports work easily from root
sys.path.append(os.path.dirname(os.getcwd()))

from firewall_tool.config_loader import ConfigLoader
from firewall_tool.platforms.windows_firewall import WindowsFirewallManager

def main():
    parser = argparse.ArgumentParser(description="Firewall Configuration Tool")
    parser.add_argument("policy_file", help="Path to the policy file (YAML/JSON)")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    parser.add_argument("--platform", choices=["windows", "linux"], default=None, help="Force platform override")

    args = parser.parse_args()

    # Detect platform
    current_os = platform.system().lower()
    target_platform = args.platform if args.platform else current_os

    print(f"Running on {current_os}, targeting {target_platform}...")

    if target_platform == "windows":
        manager = WindowsFirewallManager(dry_run=args.dry_run)
    elif target_platform == "linux":
        from firewall_tool.platforms.linux_firewall import LinuxFirewallManager
        manager = LinuxFirewallManager(dry_run=args.dry_run)
    else:
        print(f"Unsupported platform: {target_platform}")
        sys.exit(1)

    try:
        rules = ConfigLoader.load_policy(args.policy_file)
        print(f"Loaded {len(rules)} rules from {args.policy_file}")
        
        manager.apply_policy(rules)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
