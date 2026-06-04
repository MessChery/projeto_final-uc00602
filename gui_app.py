# gui_app.py
# =============================================================================
# Threat Intelligence Dashboard — Desktop GUI
# =============================================================================
# This file builds a graphical user interface (GUI) for the Phishing &
# Threat Intelligence Engine using Python's built-in tkinter library.
#
# It connects to the two backend modules already in this folder:
#   - db_queries.py  → get_threat_history(ip) : fetches threat records from DB
#   - risk_engine.py → calculate_risk(history) : returns an integer 0-100
#                      get_risk_label(score)   : returns a readable string
#
# HOW TO RUN:
#   python gui_app.py
#   (Make sure your MySQL database is running first so DB calls succeed)
# =============================================================================

import tkinter as tk            
from tkinter import messagebox
import sys
import os

# Build the absolute path to the database/ folder relative to this file
_DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database")

# Insert it at position 0 so it is searched first
if _DATABASE_DIR not in sys.path:
    sys.path.insert(0, _DATABASE_DIR)

# Now we can import the backend modules by their plain names (no package prefix)
import db_queries   
import risk_engine


# =============================================================================
# COLOR MAPPING FOR RISK LABELS
# =============================================================================
# This dictionary maps each possible risk label (returned by get_risk_label)
# to the colour that should be displayed in the result area.
# Using a dict here keeps all colour decisions in one easy-to-read place.
# =============================================================================
LABEL_COLORS = {
    "No Risk":       "#27ae60",   # Green  — safe, nothing to worry about
    "Low Risk":      "#2ecc71",   # Light green — low concern
    "Medium Risk":   "#e67e22",   # Orange — moderate concern
    "High Risk":     "#e74c3c",   # Red    — serious threat
    "Critical Risk": "#c0392b",   # Dark red — maximum danger
}

# Fallback colour when the label is unrecognised (should not normally happen)
DEFAULT_COLOR = "#ecf0f1"


# =============================================================================
# FUNCTION: analyze_ip
# =============================================================================
# Purpose:
#   This is the main "action" function — it is called every time the user
#   clicks the "Analyze Threat" button.
#
# Steps it performs:
#   1. Read the IP address the user typed in the Entry widget.
#   2. Basic validation: warn the user if the field is empty.
#   3. Call db_queries.get_threat_history(ip) to query the database.
#   4a. If NO records come back → show a "safe" message in green.
#   4b. If records ARE found   → calculate the risk score and label,
#       then display a formatted report with the correct colour.
#
# Parameters:
#   ip_entry   (tk.Entry)  - The Entry widget containing the user's IP text
#   result_var (tk.StringVar) - The StringVar linked to the result Label
#   result_lbl (tk.Label)  - The Label widget that shows the result text
# =============================================================================
def analyze_ip(ip_entry, result_var, result_lbl):

    # -----------------------------------------------------------------------
    # STEP 1 — Read and clean the IP address from the Entry widget
    # .strip() removes any accidental leading/trailing spaces the user may have
    # typed (e.g. "  192.168.1.1  " becomes "192.168.1.1")
    # -----------------------------------------------------------------------
    ip = ip_entry.get().strip()

    # -----------------------------------------------------------------------
    # STEP 2 — Validate input: do not proceed with an empty field
    # messagebox.showwarning() displays a small pop-up window with a warning
    # -----------------------------------------------------------------------
    if not ip:
        messagebox.showwarning(
            title="Input Required",
            message="Please enter an IP address before clicking Analyze."
        )
        return  # Exit the function early — nothing more to do

    # -----------------------------------------------------------------------
    # STEP 3 — Query the database for threat history of this IP
    # get_threat_history() returns a list of dicts, or an empty list []
    # -----------------------------------------------------------------------
    history = db_queries.get_threat_history(ip)  # plain name — resolved via sys.path

    # -----------------------------------------------------------------------
    # STEP 4A — No records found: IP appears safe
    # Display a reassuring green message to the user
    # -----------------------------------------------------------------------
    if not history:
        result_var.set(
            f"✅  Target IP: {ip}\n\n"
            "No threats found in database.\n"
            "IP appears safe."
        )
        result_lbl.config(fg="#27ae60")   # Green text for "safe" feedback
        return  # Done — nothing more to calculate

    # -----------------------------------------------------------------------
    # STEP 4B — Records found: calculate the risk score and display the report
    # -----------------------------------------------------------------------

    # Ask risk_engine to score the history (returns an int 0-100)
    score = risk_engine.calculate_risk(history)  # plain name — resolved via sys.path

    # Convert the numeric score to a human-readable label (e.g. "High Risk")
    label = risk_engine.get_risk_label(score)    # plain name — resolved via sys.path

    # Look up the colour for this label, defaulting to white if not found
    color = LABEL_COLORS.get(label, DEFAULT_COLOR)

    # Build the multi-line report text that will appear in the result area
    report = (
        f"🔍  Target IP:       {ip}\n\n"
        f"📊  Risk Score:      {score} / 100\n\n"
        f"🏷️   Classification:  {label}"
    )

    # Update the StringVar — this automatically updates the Label on screen
    result_var.set(report)

    # Change the text colour of the result Label to reflect the risk level
    result_lbl.config(fg=color)


# =============================================================================
# FUNCTION: build_gui
# =============================================================================
# Purpose:
#   Creates and configures the entire main window and all its widgets.
#   All layout decisions (geometry, fonts, colours, padding) live here.
#   After building everything, it hands control to tkinter's event loop.
# =============================================================================
def build_gui():

    # -----------------------------------------------------------------------
    # ROOT WINDOW
    # tk.Tk() creates the main application window
    # -----------------------------------------------------------------------
    root = tk.Tk()

    # Set the text that appears in the title bar of the window
    root.title("Threat Intelligence Dashboard")

    # Set the initial size of the window: 520 pixels wide × 420 pixels tall
    root.geometry("520x420")

    # Prevent the user from resizing the window (keeps layout tidy)
    root.resizable(False, False)

    # Background colour for the whole window — a very dark navy/charcoal
    root.configure(bg="#1a1a2e")

    # -----------------------------------------------------------------------
    # TITLE LABEL
    # Displayed at the very top of the window as a big, bold heading
    # -----------------------------------------------------------------------
    title_label = tk.Label(
        root,                                # Parent widget: the root window
        text="🛡️  Threat Intelligence Dashboard",
        font=("Arial", 16, "bold"),          # Large, bold Arial font
        fg="#e0e0e0",                        # Light grey text
        bg="#1a1a2e",                        # Match window background
        pady=10                              # Vertical padding inside the label
    )
    # pack() places the widget and makes it fill the full width horizontally
    title_label.pack(fill="x", padx=20, pady=(20, 5))

    # -----------------------------------------------------------------------
    # SUBTITLE / INSTRUCTION LABEL
    # A smaller label beneath the title to guide the user
    # -----------------------------------------------------------------------
    subtitle_label = tk.Label(
        root,
        text="Enter an IP address to check for known threats",
        font=("Arial", 10, "italic"),
        fg="#a0a0b0",                        # Muted light-purple/grey
        bg="#1a1a2e"
    )
    subtitle_label.pack(pady=(0, 15))

    # -----------------------------------------------------------------------
    # INPUT FRAME
    # A Frame acts as a container to keep the Entry and Button side by side
    # and properly spaced
    # -----------------------------------------------------------------------
    input_frame = tk.Frame(root, bg="#1a1a2e")
    input_frame.pack(padx=20, pady=(0, 10))

    # Label just to the left of the text box
    ip_label = tk.Label(
        input_frame,
        text="IP Address:",
        font=("Arial", 11),
        fg="#e0e0e0",
        bg="#1a1a2e"
    )
    ip_label.grid(row=0, column=0, padx=(0, 8), sticky="w")

    # Entry widget where the user types the IP address
    ip_entry = tk.Entry(
        input_frame,
        font=("Arial", 11),
        width=22,                            # Number of characters wide
        bg="#16213e",                        # Dark blue input background
        fg="#e0e0e0",                        # Light text colour
        insertbackground="#e0e0e0",          # Cursor colour inside the field
        relief="flat",                       # Flat border style (modern look)
        bd=4                                 # Border width (acts as padding)
    )
    ip_entry.grid(row=0, column=1, padx=(0, 10))

    # Give the Entry focus immediately so the user can type right away
    ip_entry.focus()

    # -----------------------------------------------------------------------
    # ANALYZE BUTTON
    # When clicked it calls analyze_ip(), passing the widgets it needs
    # lambda is used so we can pass arguments to the function
    # -----------------------------------------------------------------------
    analyze_btn = tk.Button(
        input_frame,
        text="Analyze Threat",
        font=("Arial", 11, "bold"),
        bg="#e94560",                        # Eye-catching red/pink accent
        fg="#ffffff",                        # White text on the button
        activebackground="#c73652",          # Slightly darker when pressed
        activeforeground="#ffffff",
        relief="flat",
        cursor="hand2",                      # Show a hand cursor on hover
        padx=12,
        pady=4,
        command=lambda: analyze_ip(ip_entry, result_var, result_lbl)
    )
    analyze_btn.grid(row=0, column=2)

    # -----------------------------------------------------------------------
    # SEPARATOR LINE
    # A thin horizontal line to visually separate the input area from results
    # -----------------------------------------------------------------------
    separator = tk.Frame(root, bg="#2a2a4a", height=2)
    separator.pack(fill="x", padx=20, pady=(5, 15))

    # -----------------------------------------------------------------------
    # RESULT AREA HEADER
    # A small label above the result box to describe what is shown below
    # -----------------------------------------------------------------------
    result_header = tk.Label(
        root,
        text="Analysis Result",
        font=("Arial", 11, "bold"),
        fg="#a0a0b0",
        bg="#1a1a2e"
    )
    result_header.pack(anchor="w", padx=25)

    # -----------------------------------------------------------------------
    # RESULT DISPLAY — StringVar + Label
    #
    # StringVar is a special tkinter variable that automatically updates the
    # Label whenever its value changes via result_var.set("new text").
    # This avoids having to call result_lbl.config(text="...") every time.
    # -----------------------------------------------------------------------
    result_var = tk.StringVar()
    result_var.set("No analysis yet.\nEnter an IP address above and click Analyze.")

    result_lbl = tk.Label(
        root,
        textvariable=result_var,             # Linked to result_var — auto-updates
        font=("Courier", 12),                # Monospace font for aligned columns
        fg="#a0a0b0",                        # Default muted grey for placeholder text
        bg="#16213e",                        # Dark blue background box
        justify="left",                      # Left-align multi-line text
        anchor="nw",                         # Anchor content to top-left corner
        width=46,                            # Fixed width in characters
        height=7,                            # Fixed height in text lines
        relief="flat",
        bd=0,
        padx=15,
        pady=12
    )
    result_lbl.pack(padx=20, pady=(5, 10))

    # -----------------------------------------------------------------------
    # FOOTER LABEL
    # A small credit/info line at the very bottom of the window
    # -----------------------------------------------------------------------
    footer_label = tk.Label(
        root,
        text="Phishing & Threat Intelligence Engine  •  UC 00602",
        font=("Arial", 8),
        fg="#4a4a6a",                        # Very muted, barely visible
        bg="#1a1a2e"
    )
    footer_label.pack(side="bottom", pady=(0, 10))

    # -----------------------------------------------------------------------
    # BIND THE ENTER / RETURN KEY
    # Pressing Enter in the Entry widget triggers the same action as clicking
    # the button — a convenience for keyboard users
    # -----------------------------------------------------------------------
    ip_entry.bind(
        "<Return>",
        lambda event: analyze_ip(ip_entry, result_var, result_lbl)
    )

    # -----------------------------------------------------------------------
    # START THE EVENT LOOP
    # root.mainloop() hands control to tkinter and keeps the window open.
    # It listens for user interactions (clicks, keypresses) until the window
    # is closed.
    # -----------------------------------------------------------------------
    root.mainloop()


# =============================================================================
# ENTRY POINT
# =============================================================================
# This block only runs when you execute this file directly:
#   python gui_app.py
#
# It does NOT run when this file is imported by another module.
# This is a Python best practice to keep modules safe to import.
# =============================================================================
if __name__ == "__main__":
    build_gui()
