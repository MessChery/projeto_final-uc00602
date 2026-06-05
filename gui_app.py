
import tkinter as tk
from tkinter import ttk
import sys
import os
import re
import socket

_DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database")
if _DATABASE_DIR not in sys.path:
    sys.path.insert(0, _DATABASE_DIR)

import db_queries
import risk_engine


BG_ROOT      = "#0f0f1a"
BG_HEADER    = "#16162a"
BG_ENTRY     = "#1c1c35"
BG_RESULT    = "#13132a"
BG_SEPARATOR = "#2a2a50"

ACCENT_RED     = "#e94560"
ACCENT_RED_HOV = "#bf3a52"
ACCENT_CLEAR   = "#252545"
ACCENT_CLEAR_H = "#363660"

SB_TROUGH  = "#1a1a30"
SB_THUMB   = "#3a3a60"
SB_THUMB_H = "#5050a0"

TEXT_PRIMARY = "#e8e8f0"
TEXT_MUTED   = "#7a7a9a"
TEXT_ACCENT  = "#a0a0cc"
TEXT_ERROR   = "#ff6b6b"
TEXT_SAFE    = "#2ecc71"
CURSOR_CLR   = "#e94560"

BORDER_RESULT = "#2a2a50"

FONT_TITLE    = ("Arial", 17, "bold")
FONT_SUBTITLE = ("Arial", 10, "italic")
FONT_LABEL_B  = ("Arial", 11, "bold")
FONT_ENTRY    = ("Courier", 11)
FONT_BTN      = ("Arial", 11, "bold")
FONT_SECTION  = ("Arial", 10, "bold")
FONT_RESULT   = ("Courier", 12)
FONT_FOOTER   = ("Arial", 8)

WIN_W, WIN_H = 620, 510


LABEL_COLORS = {
    "No Risk":       "#27ae60",
    "Low Risk":      "#2ecc71",
    "Medium Risk":   "#e67e22",
    "High Risk":     "#e74c3c",
    "Critical Risk": "#c0392b",
}

LABEL_TAGS = {
    "No Risk":       "no_risk",
    "Low Risk":      "low_risk",
    "Medium Risk":   "medium_risk",
    "High Risk":     "high_risk",
    "Critical Risk": "critical_risk",
}


_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)


def is_valid_ipv4(text: str) -> bool:
    return bool(_IPV4_RE.match(text))


def resolve_hostname(ip: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return "N/A (No PTR record)"
    except Exception:
        return "N/A (No PTR record)"


def setup_styles() -> None:

    style = ttk.Style()
    style.theme_use("clam")

    style.configure(
        "Analyze.TButton",
        font=FONT_BTN,
        background=ACCENT_RED,
        foreground="#ffffff",
        relief="flat",
        borderwidth=0,
        bordercolor=ACCENT_RED,
        lightcolor=ACCENT_RED,
        darkcolor=ACCENT_RED,
        focusthickness=0,
        focuscolor=ACCENT_RED,
        padding=(16, 8),
        anchor="center",
    )
    style.map(
        "Analyze.TButton",
        background=[("pressed", ACCENT_RED_HOV), ("active", ACCENT_RED_HOV)],
        bordercolor=[("pressed", ACCENT_RED_HOV), ("active", ACCENT_RED_HOV)],
        lightcolor=[("pressed", ACCENT_RED_HOV), ("active", ACCENT_RED_HOV)],
        darkcolor=[("pressed", ACCENT_RED_HOV),  ("active", ACCENT_RED_HOV)],
        foreground=[("pressed", "#ffffff"),       ("active", "#ffffff")],
        relief=[("pressed", "flat"),              ("active", "flat")],
    )

    style.configure(
        "Clear.TButton",
        font=FONT_BTN,
        background=ACCENT_CLEAR,
        foreground=TEXT_ACCENT,
        relief="flat",
        borderwidth=0,
        bordercolor=ACCENT_CLEAR,
        lightcolor=ACCENT_CLEAR,
        darkcolor=ACCENT_CLEAR,
        focusthickness=0,
        focuscolor=ACCENT_CLEAR,
        padding=(16, 8),
        anchor="center",
    )
    style.map(
        "Clear.TButton",
        background=[("pressed", ACCENT_CLEAR_H), ("active", ACCENT_CLEAR_H)],
        bordercolor=[("pressed", ACCENT_CLEAR_H), ("active", ACCENT_CLEAR_H)],
        lightcolor=[("pressed", ACCENT_CLEAR_H),  ("active", ACCENT_CLEAR_H)],
        darkcolor=[("pressed", ACCENT_CLEAR_H),   ("active", ACCENT_CLEAR_H)],
        foreground=[("pressed", TEXT_PRIMARY),    ("active", TEXT_PRIMARY)],
        relief=[("pressed", "flat"),              ("active", "flat")],
    )

    style.configure(
        "Dark.Vertical.TScrollbar",
        troughcolor=SB_TROUGH,
        background=SB_THUMB,
        arrowcolor=TEXT_MUTED,
        bordercolor=BG_RESULT,
        lightcolor=SB_THUMB,
        darkcolor=SB_THUMB,
        relief="flat",
        borderwidth=0,
        arrowsize=12,
    )
    style.map(
        "Dark.Vertical.TScrollbar",
        background=[("pressed", SB_THUMB_H), ("active", SB_THUMB_H)],
        lightcolor=[("pressed", SB_THUMB_H), ("active", SB_THUMB_H)],
        darkcolor=[("pressed", SB_THUMB_H),  ("active", SB_THUMB_H)],
    )


def configure_tags(text_widget: tk.Text) -> None:
    text_widget.tag_config("muted",        foreground=TEXT_MUTED)
    text_widget.tag_config("error",        foreground=TEXT_ERROR)
    text_widget.tag_config("safe",         foreground=TEXT_SAFE)
    text_widget.tag_config("no_risk",      foreground=LABEL_COLORS["No Risk"])
    text_widget.tag_config("low_risk",     foreground=LABEL_COLORS["Low Risk"])
    text_widget.tag_config("medium_risk",  foreground=LABEL_COLORS["Medium Risk"])
    text_widget.tag_config("high_risk",    foreground=LABEL_COLORS["High Risk"])
    text_widget.tag_config("critical_risk", foreground=LABEL_COLORS["Critical Risk"])


def write_result(text_widget: tk.Text, content: str, tag: str) -> None:
    text_widget.config(state=tk.NORMAL)
    text_widget.delete("1.0", tk.END)
    text_widget.insert("1.0", content, tag)
    text_widget.config(state=tk.DISABLED)


def analyze_ip(ip_entry: tk.Entry, result_text: tk.Text) -> None:

    ip = ip_entry.get().strip()

    if not ip or not is_valid_ipv4(ip):
        write_result(
            result_text,
            "⚠   Invalid Input\n\n"
            "Please enter a valid IPv4 address.\n"
            "Example:  192.168.1.1",
            "error",
        )
        return

    domain = resolve_hostname(ip)

    history = db_queries.get_threat_history(ip)

    if not history:
        write_result(
            result_text,
            f"✅  Target IP      :  {ip}\n"
            f"🌐  Resolved Domain:  {domain}\n\n"
            "No threats found in database.\n"
            "This IP appears safe.",
            "safe",
        )
        return

    score = risk_engine.calculate_risk(history)
    label = risk_engine.get_risk_label(score)
    tag   = LABEL_TAGS.get(label, "muted")

    write_result(
        result_text,
        f"🔍  Target IP      :  {ip}\n"
        f"🌐  Resolved Domain:  {domain}\n\n"
        f"📊  Risk Score     :  {score} / 100\n\n"
        f"🏷️   Classification :  {label}",
        tag,
    )


def clear_all(ip_entry: tk.Entry, result_text: tk.Text) -> None:
    ip_entry.delete(0, tk.END)
    write_result(
        result_text,
        "No analysis yet.\n"
        "Enter an IP address above and press  Analyze  or  ⏎ Enter.",
        "muted",
    )
    ip_entry.focus()


def build_gui() -> None:

    root = tk.Tk()
    root.title("Threat Intelligence Dashboard")
    root.resizable(False, False)
    root.configure(bg=BG_ROOT)

    root.update_idletasks()
    x = (root.winfo_screenwidth()  - WIN_W) // 2
    y = (root.winfo_screenheight() - WIN_H) // 2
    root.geometry(f"{WIN_W}x{WIN_H}+{x}+{y}")

    setup_styles()

    header_frame = tk.Frame(root, bg=BG_HEADER)
    header_frame.pack(fill="x")

    tk.Frame(header_frame, bg=ACCENT_RED, height=3).pack(fill="x")

    tk.Label(
        header_frame,
        text="🛡️  Threat Intelligence Dashboard",
        font=FONT_TITLE,
        fg=TEXT_PRIMARY,
        bg=BG_HEADER,
    ).pack(pady=(14, 3))

    tk.Label(
        header_frame,
        text=(
            "Real-time phishing & malicious IP analysis  •  "
            "AbuseIPDB & AlienVault OTX"
        ),
        font=FONT_SUBTITLE,
        fg=TEXT_MUTED,
        bg=BG_HEADER,
    ).pack(pady=(0, 14))

    tk.Frame(root, bg=BG_SEPARATOR, height=1).pack(fill="x")

    search_frame = tk.Frame(root, bg=BG_ROOT)
    search_frame.pack(fill="x", padx=32, pady=22)

    tk.Label(
        search_frame,
        text="IP Address :",
        font=FONT_LABEL_B,
        fg=TEXT_ACCENT,
        bg=BG_ROOT,
    ).grid(row=0, column=0, padx=(0, 10), sticky="w")

    ip_entry = tk.Entry(
        search_frame,
        font=FONT_ENTRY,
        width=20,
        bg=BG_ENTRY,
        fg=TEXT_PRIMARY,
        insertbackground=CURSOR_CLR,
        relief="flat",
        bd=6,
    )
    ip_entry.grid(row=0, column=1, padx=(0, 14), ipady=4)
    ip_entry.focus()

    ttk.Button(
        search_frame,
        text="Analyze Threat",
        style="Analyze.TButton",
        cursor="hand2",
        command=lambda: analyze_ip(ip_entry, result_text),
    ).grid(row=0, column=2, padx=(0, 8))

    ttk.Button(
        search_frame,
        text="Clear",
        style="Clear.TButton",
        cursor="hand2",
        command=lambda: clear_all(ip_entry, result_text),
    ).grid(row=0, column=3)

    ip_entry.bind("<Return>", lambda _e: analyze_ip(ip_entry, result_text))

    tk.Frame(root, bg=BG_SEPARATOR, height=1).pack(fill="x", padx=32)

    result_frame = tk.Frame(root, bg=BG_ROOT)
    result_frame.pack(fill="both", expand=True, padx=32, pady=18)

    tk.Label(
        result_frame,
        text="▸  Analysis Result",
        font=FONT_SECTION,
        fg=TEXT_ACCENT,
        bg=BG_ROOT,
        anchor="w",
    ).pack(fill="x", pady=(0, 6))

    border_frame = tk.Frame(result_frame, bg=BORDER_RESULT, bd=1, relief="flat")
    border_frame.pack(fill="both", expand=True)

    text_and_sb_frame = tk.Frame(border_frame, bg=BG_RESULT)
    text_and_sb_frame.pack(fill="both", expand=True)

    result_text = tk.Text(
        text_and_sb_frame,
        font=FONT_RESULT,
        bg=BG_RESULT,
        fg=TEXT_MUTED,
        wrap=tk.WORD,
        state=tk.DISABLED,
        relief="flat",
        bd=0,
        padx=18,
        pady=14,
        cursor="arrow",
        insertwidth=0,
        selectbackground="#2a2a50",
        selectforeground=TEXT_PRIMARY,
        inactiveselectbackground="#2a2a50",
    )
    result_text.pack(side="left", fill="both", expand=True)

    configure_tags(result_text)

    scrollbar = ttk.Scrollbar(
        text_and_sb_frame,
        orient="vertical",
        style="Dark.Vertical.TScrollbar",
        command=result_text.yview,
    )
    scrollbar.pack(side="right", fill="y")

    result_text.config(yscrollcommand=scrollbar.set)

    write_result(
        result_text,
        "No analysis yet.\n"
        "Enter an IP address above and press  Analyze  or  ⏎ Enter.",
        "muted",
    )

    tk.Label(
        root,
        text="Phishing & Threat Intelligence Engine  •  UC 00602  •  ATEC",
        font=FONT_FOOTER,
        fg="#35355a",
        bg=BG_ROOT,
    ).pack(side="bottom", pady=(0, 8))

    root.mainloop()


if __name__ == "__main__":
    build_gui()
