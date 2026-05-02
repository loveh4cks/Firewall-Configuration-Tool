import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sys
import os
import platform
import yaml
import json
import threading
import ctypes
from datetime import datetime

# ─────────────────────────────────────────────
# Paths & Constants
# ─────────────────────────────────────────────
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(APP_DIR, "firewall_tool", ".session.json")
DEFAULT_POLICY = os.path.join(APP_DIR, "firewall_tool", "policies", "default_policy.yaml")

# Ensure imports work
sys.path.insert(0, APP_DIR)

from firewall_tool.config_loader import ConfigLoader
from firewall_tool.platforms.windows_firewall import WindowsFirewallManager
from firewall_tool.platforms.linux_firewall import LinuxFirewallManager


# ─────────────────────────────────────────────
# Admin Check & Elevation
# ─────────────────────────────────────────────
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def run_as_admin_with_state():
    """Save current session state then re-launch as Administrator."""
    try:
        script = os.path.abspath(__file__)
        # The session is already saved by the caller before this function is invoked
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}"', None, 1
        )
        sys.exit(0)
    except Exception as e:
        messagebox.showerror("Elevation Failed", f"Could not get admin privileges:\n{e}")


# ─────────────────────────────────────────────
# Session Persistence
# ─────────────────────────────────────────────
def save_session(rules, current_file, active_tab=0):
    """Save session state so it survives restarts and admin elevation."""
    data = {
        "rules": rules,
        "current_file": current_file,
        "active_tab": active_tab,
        "timestamp": datetime.now().isoformat()
    }
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        with open(CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass  # Don't crash the app over session save

def load_session():
    """Load session state from disk."""
    try:
        if os.path.exists(CONFIG_FILE):
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return None

def auto_save_policy(rules):
    """Auto-save rules to the default policy file."""
    try:
        os.makedirs(os.path.dirname(DEFAULT_POLICY), exist_ok=True)
        data = {"rules": rules}
        with open(DEFAULT_POLICY, 'w') as f:
            yaml.dump(data, f, sort_keys=False, default_flow_style=False)
    except Exception:
        pass


# ─────────────────────────────────────────────
# Tooltip Helper
# ─────────────────────────────────────────────
class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, event=None):
        if self.tip_window:
            return
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            tw, text=self.text, justify=tk.LEFT,
            background="#ffffe0", foreground="#333",
            relief=tk.SOLID, borderwidth=1,
            font=("Segoe UI", 9), wraplength=320, padx=8, pady=6
        )
        label.pack()

    def hide(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None


# ─────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────
def validate_rule(rule_data):
    """Validate a rule dict. Returns (is_valid, error_messages_list)."""
    errors = []

    name = rule_data.get("name", "").strip()
    if not name:
        errors.append("Rule Name is required.")

    action = rule_data.get("action", "")
    if action not in ("allow", "block"):
        errors.append("Action must be 'allow' or 'block'.")

    direction = rule_data.get("direction", "")
    if direction not in ("inbound", "outbound"):
        errors.append("Direction must be 'inbound' or 'outbound'.")

    protocol = rule_data.get("protocol", "")
    if protocol not in ("tcp", "udp", "any"):
        errors.append("Protocol must be 'tcp', 'udp', or 'any'.")

    port = rule_data.get("port", "").strip()
    if port:
        # Port must be a number or a range like 80-443 or comma-separated
        for part in port.replace(",", " ").replace("-", " ").split():
            if not part.isdigit():
                errors.append(f"Port '{port}' is invalid. Use numbers, ranges (80-443), or comma-separated (80,443).")
                break
            val = int(part)
            if val < 1 or val > 65535:
                errors.append(f"Port {val} is out of range (1-65535).")
                break

    ip = rule_data.get("remote_ip", "").strip()
    if ip:
        # Basic IP validation
        parts = ip.split(".")
        if len(parts) != 4:
            # Could also be CIDR like 10.0.0.0/8 — allow those
            if "/" not in ip:
                errors.append(f"Remote IP '{ip}' doesn't look like a valid IPv4 address.")

    return len(errors) == 0, errors


# ─────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────
class FirewallApp:
    def __init__(self, root):
        self.root = root
        self.root.geometry("1100x720")
        self.root.minsize(900, 600)

        # Admin state
        self.admin = is_admin()
        admin_tag = "🛡️ ADMIN" if self.admin else "⚠️ NOT ADMIN"
        self.root.title(f"🔒 Firewall Configuration Tool  [{admin_tag}]")

        # State
        self.rules = []
        self.live_rules = []
        self.current_file = None
        self.selected_idx = None

        # Platform manager
        platform_name = platform.system().lower()
        if platform_name == "windows":
            self.manager = WindowsFirewallManager(dry_run=False)
            self.dry_manager = WindowsFirewallManager(dry_run=True)
        else:
            self.manager = LinuxFirewallManager(dry_run=False)
            self.dry_manager = LinuxFirewallManager(dry_run=True)

        self._setup_styles()
        self._setup_ui()

        # Handle window close — save session
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Startup log
        self.log(f"Application started. Platform: {platform.system()}")
        if self.admin:
            self.log("Running as Administrator ✅ — All features available.", "success")
        else:
            self.log("⚠️ NOT running as Administrator — Enable/Disable/Apply need Admin.", "warning")

        # Restore session
        self._restore_session()

    # ── Styles ──
    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Toolbar.TButton", padding=4, font=("Segoe UI", 9))
        style.configure("Green.TButton", foreground="green", font=("Segoe UI", 9, "bold"))
        style.configure("Red.TButton", foreground="red", font=("Segoe UI", 9, "bold"))
        style.configure("Admin.TButton", foreground="#d4a017", font=("Segoe UI", 9, "bold"))
        style.configure("Status.TLabel", font=("Segoe UI", 9), padding=4)
        style.configure("Search.TEntry", font=("Segoe UI", 10))

    # ── Main UI ──
    def _setup_ui(self):
        # ── Toolbar ──
        toolbar = ttk.Frame(self.root, padding=(5, 5))
        toolbar.pack(side=tk.TOP, fill=tk.X)

        btn_load = ttk.Button(toolbar, text="📂 Load Policy", command=self.load_policy, style="Toolbar.TButton")
        btn_load.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_load, "Load firewall rules from a YAML or JSON policy file.\nReplaces the current policy list.\nYour session is auto-saved so you can resume later.")

        btn_save = ttk.Button(toolbar, text="💾 Save Policy", command=self.save_policy, style="Toolbar.TButton")
        btn_save.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_save, "Export the current policy rules to a YAML file.\nTip: Rules are auto-saved internally, but use this\nto create a portable backup file.")

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        btn_dry = ttk.Button(toolbar, text="🧪 Apply (Dry Run)", command=lambda: self.apply_policy(dry_run=True), style="Toolbar.TButton")
        btn_dry.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_dry, "Simulate applying rules WITHOUT making changes.\nShows what commands WOULD run in the Activity Log.\nSafe to run anytime — no Admin needed.")

        btn_live = ttk.Button(toolbar, text="⚡ APPLY LIVE", command=lambda: self.apply_policy(dry_run=False), style="Red.TButton")
        btn_live.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_live, "⚠️ ACTUALLY applies rules to your firewall.\nRequires Administrator privileges.\nTest with Dry Run first!")

        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)

        btn_refresh = ttk.Button(toolbar, text="🔄 Refresh Live Rules", command=self.fetch_live_rules, style="Green.TButton")
        btn_refresh.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_refresh, "Fetch all active firewall rules from your OS.\nShows ports, protocols, and enabled status.\nYou can search, enable, or disable rules.")

        if not self.admin:
            ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=8, fill=tk.Y)
            btn_admin = ttk.Button(toolbar, text="🛡️ Run as Admin", command=self._elevate_as_admin, style="Admin.TButton")
            btn_admin.pack(side=tk.LEFT, padx=3)
            ToolTip(btn_admin, "Restart as Administrator.\nYour current rules and session are saved automatically\nand will be restored after restart.")

        # ── Main Paned Window ──
        main_pane = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        main_pane.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        top_pane = ttk.PanedWindow(main_pane, orient=tk.HORIZONTAL)
        main_pane.add(top_pane, weight=3)

        # ── LEFT: Notebook ──
        left_frame = ttk.Frame(top_pane)
        top_pane.add(left_frame, weight=2)

        self.notebook = ttk.Notebook(left_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # ── TAB 1: Policy Rules ──
        policy_tab = ttk.Frame(self.notebook)
        self.notebook.add(policy_tab, text="📋 Policy Rules")

        policy_search_frame = ttk.Frame(policy_tab, padding=(2, 4))
        policy_search_frame.pack(fill=tk.X)
        ttk.Label(policy_search_frame, text="🔍").pack(side=tk.LEFT, padx=(2, 4))
        self.policy_search_var = tk.StringVar()
        self.policy_search_var.trace_add("write", self._on_policy_search)
        policy_search_entry = ttk.Entry(policy_search_frame, textvariable=self.policy_search_var, style="Search.TEntry")
        policy_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ToolTip(policy_search_entry, "Search policy rules by name, action, direction, protocol, port, or IP.")
        btn_clear_p = ttk.Button(policy_search_frame, text="✕", width=3, command=lambda: self.policy_search_var.set(""))
        btn_clear_p.pack(side=tk.LEFT)

        self.tree = ttk.Treeview(policy_tab, columns=("name", "action", "direction", "protocol", "port", "remote_ip"), show="headings", selectmode="browse")
        self.tree.heading("name", text="Rule Name")
        self.tree.heading("action", text="Action")
        self.tree.heading("direction", text="Direction")
        self.tree.heading("protocol", text="Protocol")
        self.tree.heading("port", text="Port")
        self.tree.heading("remote_ip", text="Remote IP")
        self.tree.column("name", width=150)
        self.tree.column("action", width=60)
        self.tree.column("direction", width=75)
        self.tree.column("protocol", width=60)
        self.tree.column("port", width=60)
        self.tree.column("remote_ip", width=100)

        tree_scroll = ttk.Scrollbar(policy_tab, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewSelect>>", self.on_rule_select)

        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill=tk.X, pady=3)
        btn_add = ttk.Button(btn_frame, text="➕ Add New Rule", command=self.add_rule)
        btn_add.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_add, "Add a new rule to the policy list.\nEdit it in the Rule Editor, then click Save Changes.")

        btn_del = ttk.Button(btn_frame, text="🗑️ Delete Rule", command=self.delete_rule)
        btn_del.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_del, "Remove the selected rule from the policy list.\nThis does NOT remove it from the live firewall.")

        # ── TAB 2: Live Firewall Rules ──
        live_tab = ttk.Frame(self.notebook)
        self.notebook.add(live_tab, text="🌐 Live Firewall Rules")

        live_search_frame = ttk.Frame(live_tab, padding=(2, 4))
        live_search_frame.pack(fill=tk.X)
        ttk.Label(live_search_frame, text="🔍").pack(side=tk.LEFT, padx=(2, 4))
        self.live_search_var = tk.StringVar()
        self.live_search_var.trace_add("write", self._on_live_search)
        live_search_entry = ttk.Entry(live_search_frame, textvariable=self.live_search_var, style="Search.TEntry")
        live_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 4))
        ToolTip(live_search_entry, "Search live rules by name, direction, action,\nprotocol, port, or enabled status.")
        btn_clear_l = ttk.Button(live_search_frame, text="✕", width=3, command=lambda: self.live_search_var.set(""))
        btn_clear_l.pack(side=tk.LEFT)

        self.live_tree = ttk.Treeview(live_tab, columns=("name", "direction", "action", "enabled", "protocol", "port"), show="headings", selectmode="browse")
        self.live_tree.heading("name", text="Rule Name")
        self.live_tree.heading("direction", text="Direction")
        self.live_tree.heading("action", text="Action")
        self.live_tree.heading("enabled", text="Enabled")
        self.live_tree.heading("protocol", text="Protocol")
        self.live_tree.heading("port", text="Port")
        self.live_tree.column("name", width=180)
        self.live_tree.column("direction", width=75)
        self.live_tree.column("action", width=60)
        self.live_tree.column("enabled", width=60)
        self.live_tree.column("protocol", width=60)
        self.live_tree.column("port", width=80)

        live_scroll = ttk.Scrollbar(live_tab, orient=tk.VERTICAL, command=self.live_tree.yview)
        self.live_tree.configure(yscrollcommand=live_scroll.set)
        self.live_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        live_scroll.pack(side=tk.RIGHT, fill=tk.Y)

        live_btn_frame = ttk.Frame(left_frame)
        live_btn_frame.pack(fill=tk.X, pady=3)

        btn_enable = ttk.Button(live_btn_frame, text="✅ Enable Rule", command=self.toggle_enable_rule, style="Green.TButton")
        btn_enable.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_enable, "Enable the selected live firewall rule.\nRequires Administrator/root privileges.")

        btn_disable = ttk.Button(live_btn_frame, text="🚫 Disable Rule", command=self.toggle_disable_rule, style="Red.TButton")
        btn_disable.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_disable, "Disable the selected live firewall rule.\nTurns it OFF without deleting.\nRequires Administrator/root privileges.")

        btn_delete_live = ttk.Button(live_btn_frame, text="🗑️ Delete Live Rule", command=self.delete_live_rule, style="Red.TButton")
        btn_delete_live.pack(side=tk.LEFT, padx=3)
        ToolTip(btn_delete_live, "Permanently delete the selected live rule from the firewall.\nThe rule will be disabled first, then removed.\n⚠️ This cannot be undone!\nRequires Administrator/root privileges.")

        btn_refresh2 = ttk.Button(live_btn_frame, text="🔄 Refresh", command=self.fetch_live_rules)
        btn_refresh2.pack(side=tk.LEFT, padx=3)

        # ── RIGHT: Rule Editor ──
        right_frame = ttk.Labelframe(top_pane, text="📝 Rule Editor", padding=10)
        top_pane.add(right_frame, weight=1)

        self.vars = {
            "name": tk.StringVar(),
            "action": tk.StringVar(value="allow"),
            "direction": tk.StringVar(value="inbound"),
            "protocol": tk.StringVar(value="tcp"),
            "port": tk.StringVar(),
            "remote_ip": tk.StringVar()
        }

        row = 0
        lbl = ttk.Label(right_frame, text="Rule Name: *")
        lbl.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl, "REQUIRED. A descriptive name for this rule.\nExample: 'Allow Web Traffic' or 'Block SSH'.")
        ttk.Entry(right_frame, textvariable=self.vars["name"]).grid(row=row, column=1, sticky="ew", pady=5)

        row += 1
        lbl_action = ttk.Label(right_frame, text="Action: *")
        lbl_action.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl_action, "REQUIRED. What to do with matching traffic:\n• Allow — Let traffic through\n• Block — Drop/reject traffic")
        action_frm = ttk.Frame(right_frame)
        action_frm.grid(row=row, column=1, sticky="w")
        rb_allow = ttk.Radiobutton(action_frm, text="Allow", variable=self.vars["action"], value="allow")
        rb_allow.pack(side=tk.LEFT)
        ToolTip(rb_allow, "ALLOW: Permit this traffic through the firewall.")
        rb_block = ttk.Radiobutton(action_frm, text="Block", variable=self.vars["action"], value="block")
        rb_block.pack(side=tk.LEFT, padx=10)
        ToolTip(rb_block, "BLOCK: Deny/drop this traffic at the firewall.")

        row += 1
        lbl_dir = ttk.Label(right_frame, text="Direction: *")
        lbl_dir.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl_dir, "REQUIRED. The direction of traffic:\n• Inbound — Traffic coming IN (e.g., clients connecting to your server)\n• Outbound — Traffic going OUT (e.g., your browser visiting a site)")
        dir_frm = ttk.Frame(right_frame)
        dir_frm.grid(row=row, column=1, sticky="w")
        rb_in = ttk.Radiobutton(dir_frm, text="Inbound", variable=self.vars["direction"], value="inbound")
        rb_in.pack(side=tk.LEFT)
        ToolTip(rb_in, "INBOUND: Traffic arriving from the network.\nExample: A client connecting to your web server on port 80.")
        rb_out = ttk.Radiobutton(dir_frm, text="Outbound", variable=self.vars["direction"], value="outbound")
        rb_out.pack(side=tk.LEFT, padx=10)
        ToolTip(rb_out, "OUTBOUND: Traffic leaving your computer.\nExample: Your browser connecting to google.com.")

        row += 1
        lbl_proto = ttk.Label(right_frame, text="Protocol: *")
        lbl_proto.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl_proto, "REQUIRED. Network protocol:\n• TCP — Used by most apps (web, email, SSH)\n• UDP — Used for DNS, streaming, gaming\n• Any — Match all protocols (can't specify port)")
        cmb_proto = ttk.Combobox(right_frame, textvariable=self.vars["protocol"], values=["tcp", "udp", "any"], state="readonly")
        cmb_proto.grid(row=row, column=1, sticky="ew")
        ToolTip(cmb_proto, "Select protocol:\n• TCP — Reliable (HTTP, SSH, FTP)\n• UDP — Fast (DNS, streaming)\n• Any — All protocols\n\n⚠️ If you specify a Port with 'Any', it auto-defaults to TCP.")

        row += 1
        lbl_port = ttk.Label(right_frame, text="Port:")
        lbl_port.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl_port, "Optional. Target port number (1-65535).\nCommon: 80 (HTTP), 443 (HTTPS), 22 (SSH),\n3389 (RDP), 53 (DNS).\nLeave empty to match all ports.")
        ttk.Entry(right_frame, textvariable=self.vars["port"]).grid(row=row, column=1, sticky="ew")

        row += 1
        lbl_ip = ttk.Label(right_frame, text="Remote IP:")
        lbl_ip.grid(row=row, column=0, sticky="w", pady=5)
        ToolTip(lbl_ip, "Optional. Specific IP to target.\nExample: 192.168.1.100\nLeave empty for ALL addresses.")
        ttk.Entry(right_frame, textvariable=self.vars["remote_ip"]).grid(row=row, column=1, sticky="ew")

        row += 1
        # Required fields note
        ttk.Label(right_frame, text="* = required field", font=("Segoe UI", 8, "italic"), foreground="gray").grid(row=row, column=0, columnspan=2, sticky="w", pady=(0, 5))

        row += 1
        btn_save = ttk.Button(right_frame, text="💾 Save Changes to List", command=self.update_rule_from_form, style="Green.TButton")
        btn_save.grid(row=row, column=0, columnspan=2, sticky="ew", pady=10)
        ToolTip(btn_save, "Save this rule into the policy list.\nIf a rule is selected, it updates that rule.\nIf nothing is selected, a new rule is added.\nAll rules are auto-saved to disk.")

        row += 1
        btn_clear = ttk.Button(right_frame, text="🔄 Clear Form", command=self._clear_form)
        btn_clear.grid(row=row, column=0, columnspan=2, sticky="ew")
        ToolTip(btn_clear, "Clear the form to start adding a brand new rule.\nDeselects the current selection in the list.")

        right_frame.columnconfigure(1, weight=1)

        # ── BOTTOM: Activity Log ──
        log_frame = ttk.Labelframe(main_pane, text="📜 Activity Log", padding=5)
        main_pane.add(log_frame, weight=1)

        self.log_text = tk.Text(log_frame, height=8, wrap=tk.WORD, font=("Consolas", 9), bg="#1e1e1e", fg="#d4d4d4", insertbackground="white")
        log_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        log_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text.configure(state=tk.DISABLED)

        self.log_text.tag_configure("info", foreground="#9cdcfe")
        self.log_text.tag_configure("success", foreground="#6a9955")
        self.log_text.tag_configure("error", foreground="#f44747")
        self.log_text.tag_configure("warning", foreground="#dcdcaa")
        self.log_text.tag_configure("command", foreground="#ce9178")

        # ── Status Bar ──
        admin_hint = "" if self.admin else " | ⚠️ Run as Admin for full features"
        self.status = tk.StringVar(value=f"Ready{admin_hint}")
        ttk.Label(self.root, textvariable=self.status, style="Status.TLabel", relief=tk.SUNKEN, anchor="w").pack(side=tk.BOTTOM, fill=tk.X)

    # ─────────────────────────────────────────────
    # Session Management
    # ─────────────────────────────────────────────
    def _restore_session(self):
        """Restore the last session on startup."""
        session = load_session()
        if session and session.get("rules"):
            self.rules = session["rules"]
            self.current_file = session.get("current_file")
            self.refresh_policy_list()
            source = os.path.basename(self.current_file) if self.current_file else "last session"
            self.log(f"Restored {len(self.rules)} rules from {source}", "success")
            self.status.set(f"Resumed session — {len(self.rules)} rules loaded from {source}")

            # Restore active tab
            try:
                tab = session.get("active_tab", 0)
                self.notebook.select(tab)
            except Exception:
                pass
        elif os.path.exists(DEFAULT_POLICY):
            # Load default policy
            try:
                self.rules = ConfigLoader.load_policy(DEFAULT_POLICY)
                self.refresh_policy_list()
                self.log(f"Loaded default policy ({len(self.rules)} rules)", "info")
            except Exception:
                self.log("No previous session found. Start by adding rules or loading a policy.", "info")
        else:
            self.log("No previous session found. Start by adding rules or loading a policy.", "info")

    def _save_session(self):
        """Save current session to disk."""
        active_tab = self.notebook.index(self.notebook.select()) if self.notebook.select() else 0
        save_session(self.rules, self.current_file, active_tab)
        auto_save_policy(self.rules)

    def _on_close(self):
        """Handle window close — save session and exit."""
        self._save_session()
        self.root.destroy()

    def _elevate_as_admin(self):
        """Save session then restart as admin."""
        self._save_session()
        self.log("Saving session and restarting as Administrator...", "warning")
        run_as_admin_with_state()

    # ─────────────────────────────────────────────
    # Logging
    # ─────────────────────────────────────────────
    def log(self, message, tag="info"):
        self.log_text.configure(state=tk.NORMAL)
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n", tag)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    # ─────────────────────────────────────────────
    # Search Filtering
    # ─────────────────────────────────────────────
    def _on_policy_search(self, *args):
        query = self.policy_search_var.get().lower().strip()
        self.refresh_policy_list(filter_query=query)

    def _on_live_search(self, *args):
        query = self.live_search_var.get().lower().strip()
        self._refresh_live_tree(filter_query=query)

    # ─────────────────────────────────────────────
    # Admin Check
    # ─────────────────────────────────────────────
    def _check_admin(self, action_name="This action"):
        if not self.admin:
            result = messagebox.askyesno(
                "Administrator Required",
                f"{action_name} requires Administrator privileges.\n\n"
                "Would you like to save your session and restart as Administrator?\n"
                "(Your rules and current state will be preserved)"
            )
            if result:
                self._elevate_as_admin()
            return False
        return True

    # ─────────────────────────────────────────────
    # Clear Form
    # ─────────────────────────────────────────────
    def _clear_form(self):
        """Clear the editor form and deselect tree."""
        self.vars["name"].set("")
        self.vars["action"].set("allow")
        self.vars["direction"].set("inbound")
        self.vars["protocol"].set("tcp")
        self.vars["port"].set("")
        self.vars["remote_ip"].set("")
        # Deselect
        for item in self.tree.selection():
            self.tree.selection_remove(item)
        self.selected_idx = None
        self.status.set("Form cleared — fill in details and click 'Save Changes to List' to add a new rule")

    # ─────────────────────────────────────────────
    # Policy Management
    # ─────────────────────────────────────────────
    def load_policy(self):
        path = filedialog.askopenfilename(filetypes=[("YAML Files", "*.yaml *.yml"), ("JSON Files", "*.json"), ("All", "*.*")])
        if path:
            try:
                loaded_rules = ConfigLoader.load_policy(path)
                # Validate all rules
                invalid = []
                for i, rule in enumerate(loaded_rules):
                    valid, errs = validate_rule(rule)
                    if not valid:
                        invalid.append(f"Rule {i+1} ({rule.get('name','unnamed')}): {'; '.join(errs)}")

                if invalid:
                    msg = "Some rules have issues:\n\n" + "\n".join(invalid[:5])
                    if len(invalid) > 5:
                        msg += f"\n...and {len(invalid)-5} more"
                    msg += "\n\nLoad anyway?"
                    if not messagebox.askyesno("Validation Warning", msg):
                        return

                self.rules = loaded_rules
                self.current_file = path
                self.refresh_policy_list()
                self._save_session()
                self.status.set(f"Loaded {len(self.rules)} rules from {os.path.basename(path)}")
                self.log(f"Loaded policy: {os.path.basename(path)} ({len(self.rules)} rules)", "success")
            except Exception as e:
                messagebox.showerror("Load Error", str(e))
                self.log(f"Failed to load policy: {e}", "error")

    def save_policy(self):
        if not self.rules:
            messagebox.showwarning("No Rules", "No rules to save. Add some first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".yaml", filetypes=[("YAML Files", "*.yaml")])
        if path:
            try:
                data = {"rules": self.rules}
                with open(path, 'w') as f:
                    yaml.dump(data, f, sort_keys=False, default_flow_style=False)
                self.current_file = path
                self._save_session()
                self.status.set(f"Exported {len(self.rules)} rules to {os.path.basename(path)}")
                self.log(f"Policy exported to: {os.path.basename(path)}", "success")
            except Exception as e:
                messagebox.showerror("Save Error", str(e))
                self.log(f"Failed to export policy: {e}", "error")

    def refresh_policy_list(self, filter_query=""):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for idx, rule in enumerate(self.rules):
            values = (
                rule.get("name", "Unnamed"),
                rule.get("action", "—"),
                rule.get("direction", "—"),
                rule.get("protocol", "—"),
                rule.get("port", "Any"),
                rule.get("remote_ip", "Any")
            )
            if filter_query:
                combined = " ".join(str(v).lower() for v in values)
                if filter_query not in combined:
                    continue
            self.tree.insert("", "end", iid=str(idx), values=values)

    def on_rule_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        idx = int(selected[0])
        self.selected_idx = idx
        rule = self.rules[idx]

        self.vars["name"].set(rule.get("name", ""))
        self.vars["action"].set(rule.get("action", "allow"))
        self.vars["direction"].set(rule.get("direction", "inbound"))
        self.vars["protocol"].set(rule.get("protocol", "tcp"))
        self.vars["port"].set(str(rule.get("port", "")))
        self.vars["remote_ip"].set(rule.get("remote_ip", ""))

    def add_rule(self):
        new_rule = {
            "name": f"New Rule {len(self.rules)+1}",
            "action": "allow",
            "direction": "inbound",
            "protocol": "tcp",
        }
        self.rules.append(new_rule)
        self.policy_search_var.set("")
        self.refresh_policy_list()
        new_idx = str(len(self.rules) - 1)
        self.tree.selection_set(new_idx)
        self.tree.see(new_idx)
        self.on_rule_select(None)
        self._save_session()
        self.log(f"Added new rule: {new_rule['name']}", "success")
        self.status.set("New rule added — edit details on the right, then click 'Save Changes to List'")

    def delete_rule(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a rule from the list first.")
            return
        idx = int(selected[0])
        name = self.rules[idx].get("name", "Unnamed")
        if messagebox.askyesno("Confirm Delete", f"Remove rule '{name}' from the policy list?"):
            del self.rules[idx]
            self.refresh_policy_list()
            self.selected_idx = None
            self._save_session()
            self.log(f"Deleted rule: {name}", "warning")
            self.status.set(f"Rule '{name}' removed")

    def update_rule_from_form(self):
        """Save form data into the rules list with full validation."""
        rule_data = {
            "name": self.vars["name"].get().strip(),
            "action": self.vars["action"].get(),
            "direction": self.vars["direction"].get(),
            "protocol": self.vars["protocol"].get(),
        }

        port = self.vars["port"].get().strip()
        if port:
            rule_data["port"] = port

        ip = self.vars["remote_ip"].get().strip()
        if ip:
            rule_data["remote_ip"] = ip

        # Validate
        is_valid, errors = validate_rule(rule_data)
        if not is_valid:
            error_msg = "Please fix the following:\n\n• " + "\n• ".join(errors)
            messagebox.showwarning("Validation Error", error_msg)
            self.log(f"Validation failed: {'; '.join(errors)}", "error")
            return

        name = rule_data["name"]
        selected = self.tree.selection()
        if selected:
            idx = int(selected[0])
            self.rules[idx] = rule_data
            self.log(f"Updated rule: {name} — {rule_data['action']}/{rule_data['direction']}/{rule_data['protocol']}, Port: {port or 'Any'}, IP: {ip or 'Any'}", "success")
            self.status.set(f"Rule '{name}' updated and auto-saved")
        else:
            self.rules.append(rule_data)
            self.log(f"Added new rule: {name}", "success")
            self.status.set(f"Rule '{name}' added and auto-saved")

        self.refresh_policy_list()
        self._save_session()

    # ─────────────────────────────────────────────
    # Apply Policy
    # ─────────────────────────────────────────────
    def apply_policy(self, dry_run):
        if not self.rules:
            messagebox.showwarning("No Rules", "No rules in the list. Add some first.")
            return

        # Validate all rules before applying
        issues = []
        for i, rule in enumerate(self.rules):
            valid, errs = validate_rule(rule)
            if not valid:
                issues.append(f"Rule '{rule.get('name', f'#{i+1}')}': {'; '.join(errs)}")

        if issues:
            msg = "Fix these rules before applying:\n\n" + "\n".join(issues[:5])
            if len(issues) > 5:
                msg += f"\n...and {len(issues)-5} more"
            messagebox.showerror("Validation Error", msg)
            return

        if not dry_run and not self._check_admin("Applying firewall rules"):
            return

        mode = "DRY RUN" if dry_run else "LIVE"
        self.log(f"═══ Applying {len(self.rules)} rules ({mode}) ═══", "warning")
        self.status.set(f"Applying rules ({mode})...")

        manager = self.dry_manager if dry_run else self.manager
        manager.clear_log()

        try:
            manager.apply_policy(self.rules)

            for entry in manager.get_log():
                if "[ERROR]" in entry or "[FAILED]" in entry:
                    self.log(entry, "error")
                elif "[SUCCESS]" in entry:
                    self.log(entry, "success")
                elif "[DRY RUN]" in entry:
                    self.log(entry, "command")
                elif "[WARNING]" in entry:
                    self.log(entry, "warning")
                else:
                    self.log(entry, "info")

            self.log(f"═══ Policy application complete ({mode}) ═══", "warning")
            self.status.set(f"Done — {len(self.rules)} rules processed ({mode})")

            if not dry_run:
                messagebox.showinfo("Complete", f"{len(self.rules)} rules applied.\nCheck the Activity Log for details.")
        except Exception as e:
            self.log(f"CRITICAL ERROR: {e}", "error")
            messagebox.showerror("Error", str(e))

    # ─────────────────────────────────────────────
    # Live Firewall Rules
    # ─────────────────────────────────────────────
    def fetch_live_rules(self):
        self.log("Fetching live firewall rules... (this may take a moment)", "warning")
        self.status.set("Fetching live firewall rules...")
        self.notebook.select(1)

        def _fetch():
            try:
                # Use the actual (non-dry-run) manager for the current platform
                platform_name = platform.system().lower()
                if platform_name == "windows":
                    fetch_manager = WindowsFirewallManager(dry_run=False)
                else:
                    fetch_manager = LinuxFirewallManager(dry_run=False)
                rules = fetch_manager.list_rules()
                self.root.after(0, lambda: self._on_live_rules_fetched(rules))
            except Exception as e:
                self.root.after(0, lambda err=e: self.log(f"Error fetching live rules: {err}", "error"))
                self.root.after(0, lambda: self.status.set("Error fetching live rules"))

        threading.Thread(target=_fetch, daemon=True).start()

    def _on_live_rules_fetched(self, rules):
        self.live_rules = rules
        self._refresh_live_tree()
        self.log(f"Loaded {len(rules)} live firewall rules", "success")
        self.status.set(f"Showing {len(rules)} live rules — Use Enable/Disable to toggle")

    def _refresh_live_tree(self, filter_query=""):
        if not filter_query:
            filter_query = self.live_search_var.get().lower().strip()

        for item in self.live_tree.get_children():
            self.live_tree.delete(item)

        for idx, rule in enumerate(self.live_rules):
            enabled_text = "✅ Yes" if rule.get("enabled", False) else "❌ No"
            values = (
                rule.get("name", "Unknown"),
                rule.get("direction", "—"),
                rule.get("action", "—"),
                enabled_text,
                rule.get("protocol", "—"),
                rule.get("port", "Any")
            )
            if filter_query:
                combined = " ".join(str(v).lower() for v in values)
                if filter_query not in combined:
                    continue
            self.live_tree.insert("", "end", iid=str(idx), values=values)

    def _get_selected_live_rule(self):
        selected = self.live_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a rule from the Live Firewall Rules list.")
            return None
        idx = int(selected[0])
        rule_name = self.live_rules[idx].get("name", "")
        return idx, rule_name

    def toggle_enable_rule(self):
        if not self._check_admin("Enabling a firewall rule"):
            return
        sel = self._get_selected_live_rule()
        if not sel:
            return
        idx, rule_name = sel
        self.log(f"Enabling rule: {rule_name}...", "warning")
        self.status.set(f"Enabling '{rule_name}'...")

        def _do():
            success, msg = self.manager.enable_rule(rule_name)
            self.root.after(0, lambda: self._on_toggle_done(rule_name, "enable", success, msg))

        threading.Thread(target=_do, daemon=True).start()

    def toggle_disable_rule(self):
        if not self._check_admin("Disabling a firewall rule"):
            return
        sel = self._get_selected_live_rule()
        if not sel:
            return
        idx, rule_name = sel

        if not messagebox.askyesno("Confirm Disable", f"Disable firewall rule: '{rule_name}'?\n\nThis turns it OFF (can be re-enabled later)."):
            return

        self.log(f"Disabling rule: {rule_name}...", "warning")
        self.status.set(f"Disabling '{rule_name}'...")

        def _do():
            success, msg = self.manager.disable_rule(rule_name)
            self.root.after(0, lambda: self._on_toggle_done(rule_name, "disable", success, msg))

        threading.Thread(target=_do, daemon=True).start()

    def _on_toggle_done(self, rule_name, action, success, msg):
        if success:
            past = "enabled" if action == "enable" else "disabled"
            self.log(f"Rule '{rule_name}' {past} successfully.", "success")
            self.status.set(f"Rule '{rule_name}' {past} — Refreshing...")
            self.fetch_live_rules()
        else:
            self.log(f"Failed to {action} '{rule_name}': {msg}", "error")
            if "Access is denied" in msg or "Permission denied" in msg:
                messagebox.showerror(
                    "Access Denied",
                    f"Could not {action} rule '{rule_name}'.\n\n"
                    "You need Administrator/root privileges.\n"
                    "Click '🛡️ Run as Admin' — your session will be preserved."
                )
            else:
                messagebox.showerror("Error", f"Failed to {action} rule.\n\n{msg}")

    def delete_live_rule(self):
        """Delete a live firewall rule (disables first, then removes)."""
        if not self._check_admin("Deleting a firewall rule"):
            return
        sel = self._get_selected_live_rule()
        if not sel:
            return
        idx, rule_name = sel

        # Confirm with user
        is_enabled = self.live_rules[idx].get("enabled", False)
        warn = ""
        if is_enabled:
            warn = "\n\nThis rule is currently ENABLED. It will be disabled first, then deleted."

        if not messagebox.askyesno(
            "⚠️ Confirm Delete",
            f"Permanently delete firewall rule:\n\n'{rule_name}'?{warn}\n\n"
            "This CANNOT be undone. You would need to re-create the rule manually."
        ):
            return

        self.log(f"Deleting live rule: {rule_name}...", "warning")
        self.status.set(f"Deleting '{rule_name}'...")

        def _do():
            success, msg = self.manager.delete_rule(rule_name)
            def _done():
                if success:
                    self.log(f"Rule '{rule_name}' deleted successfully.", "success")
                    self.status.set(f"Rule '{rule_name}' deleted — Refreshing...")
                    self.fetch_live_rules()
                else:
                    self.log(f"Failed to delete '{rule_name}': {msg}", "error")
                    if "Access is denied" in msg or "Permission denied" in msg:
                        messagebox.showerror(
                            "Access Denied",
                            f"Could not delete rule '{rule_name}'.\n\n"
                            "You need Administrator/root privileges."
                        )
                    else:
                        messagebox.showerror("Error", f"Failed to delete rule.\n\n{msg}")
            self.root.after(0, _done)

        threading.Thread(target=_do, daemon=True).start()


# ─────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────
if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallApp(root)
    root.mainloop()
