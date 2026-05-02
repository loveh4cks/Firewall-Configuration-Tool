# 🔥 Firewall Configuration Tool

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?logo=linux)
![License](https://img.shields.io/badge/License-MIT-green)
![GUI](https://img.shields.io/badge/Interface-CLI%20%26%20GUI-orange)

A cross-platform firewall management tool built in Python. Define your firewall rules once in a simple **YAML policy file**, and apply them on **Windows** (via PowerShell / `netsh`) or **Linux** (via `iptables`) — with a full **GUI** and **CLI** interface.

---

## ✨ Features

- 🖥️ **GUI Mode** — Visual rule manager with real-time feedback
- 🖱️ **CLI Mode** — Scriptable command-line interface
- 🔒 **Dry Run** — Preview commands safely before applying
- 📜 **YAML Policies** — Portable, human-readable rule definitions
- 🪟 **Windows Support** — Uses PowerShell `New-NetFirewallRule`
- 🐧 **Linux Support** — Uses `iptables` commands
- 🔄 **Session Persistence** — Rules are saved and restored across sessions
- 🛡️ **Input Validation** — Prevents malformed rules from being applied

---

## 📋 Prerequisites

| Requirement | Details |
|---|---|
| Python | 3.8 or higher |
| OS | Windows 10/11 or Linux |
| Privileges | Administrator (Windows) or root/sudo (Linux) |
| Dependencies | `pyyaml`, `tkinter` (built-in) |

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/firewall-configuration-tool.git
cd firewall-configuration-tool

# Install dependencies
pip install pyyaml
```

---

## 💻 Usage

### GUI Mode *(Recommended)*

Launch the full graphical interface to visually add, remove, enable, or disable firewall rules.

```bash
python gui.py
```

### CLI Mode

#### Dry Run (Safe Preview)
Check what commands would be executed **without** applying any changes.

```bash
python main.py firewall_tool/policies/sample_policy.yaml --dry-run
```

#### Apply Rules
> ⚠️ **Warning**: This modifies your active firewall. Ensure you don't lock yourself out (especially over SSH/RDP).

```bash
python main.py firewall_tool/policies/sample_policy.yaml
```

#### Force Platform Override
Test against a specific platform regardless of your actual OS (useful for dry-run testing).

```bash
python main.py firewall_tool/policies/sample_policy.yaml --dry-run --platform linux
python main.py firewall_tool/policies/sample_policy.yaml --dry-run --platform windows
```

---

## 📄 Policy File Format

Policies are written in YAML. Place them in `firewall_tool/policies/`.

```yaml
rules:
  - name: "Allow HTTP"
    action: "allow"
    protocol: "tcp"
    port: 80
    direction: "inbound"

  - name: "Allow HTTPS"
    action: "allow"
    protocol: "tcp"
    port: 443
    direction: "inbound"

  - name: "Block Suspicious IP"
    action: "block"
    protocol: "any"
    remote_ip: "10.10.10.10"
    direction: "inbound"
```

### Supported Fields

| Field | Values | Required |
|---|---|---|
| `name` | Any string | ✅ |
| `action` | `allow`, `block` | ✅ |
| `direction` | `inbound`, `outbound` | ✅ |
| `protocol` | `tcp`, `udp`, `any` | ✅ |
| `port` | Port number (e.g. `80`) | ❌ |
| `remote_ip` | IP address or CIDR | ❌ |

---

## 🗂️ Project Structure

```
firewall-configuration-tool/
├── gui.py                          # Tkinter GUI application
├── main.py                         # CLI entry point
├── firewall_tool/
│   ├── __init__.py
│   ├── config_loader.py            # YAML policy parser
│   ├── firewall_manager.py         # Abstract base manager
│   ├── platforms/
│   │   ├── windows_firewall.py     # Windows PowerShell implementation
│   │   └── linux_firewall.py       # Linux iptables implementation
│   └── policies/
│       ├── sample_policy.yaml      # Example policy
│       └── default_policy.yaml     # Default rules applied on startup
```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue first to discuss what you'd like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
