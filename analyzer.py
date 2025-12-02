# analyzer.py
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime
import re

def run_analyzer():
    # ------------------------------
    # CONFIG & STATE
    # ------------------------------
    LOG_PATTERN = re.compile(r"\[(.*?)\]\s+(LOGIN FAILED|LOGIN SUCCESS|REGISTER FAILED|REGISTER SUCCESS)\s+-\s+username='(.*?)'")
    FAIL_WINDOW = 60
    FAIL_THRESHOLD = 4
    RAPID_THRESHOLD = 2
    UNUSUAL_HOURS = range(0, 6)
    DAILY_FAIL_LIMIT = 20

    logs = []
    raw_data = []
    last_attempt = {}
    fail_times = {}
    daily_fails = {}

    # ------------------------------
    # FUNCTIONS
    # ------------------------------
    def load_logs():
        nonlocal logs, raw_data
        try:
            with open("logs.txt", "r") as f:
                raw_data = f.readlines()
        except FileNotFoundError:
            messagebox.showerror("Error", "logs.txt not found.")
            return
        logs.clear()
        for line in raw_data:
            match = LOG_PATTERN.search(line)
            if match:
                timestamp = datetime.strptime(match.group(1), "%Y-%m-%d %H:%M:%S")
                status = match.group(2)
                user = match.group(3)
                logs.append((timestamp, status, user))
        logs.sort(key=lambda x: x[0])
        output.insert(tk.END, f"Loaded {len(logs)} log entries.\n")

    def show_raw_logs():
        if not raw_data:
            messagebox.showwarning("No Logs", "Load logs first.")
            return
        output.insert(tk.END, "\n=== Raw Logs ===\n")
        for line in raw_data:
            output.insert(tk.END, line)
        output.insert(tk.END, "================\n\n")

    def analyze_logs():
        nonlocal last_attempt, fail_times, daily_fails
        if not logs:
            messagebox.showwarning("No Logs", "Load logs first.")
            return

        suspicious = []
        last_attempt.clear()
        fail_times.clear()
        daily_fails.clear()

        for timestamp, status, user in logs:
            # Rapid attempts
            if user in last_attempt:
                delta = (timestamp - last_attempt[user]).total_seconds()
                if delta < RAPID_THRESHOLD:
                    suspicious.append(f"[{timestamp}] Rapid login attempts by '{user}' ({delta:.1f}s apart)")
            last_attempt[user] = timestamp

            # Unusual hours
            if status == "LOGIN SUCCESS" and timestamp.hour in UNUSUAL_HOURS:
                suspicious.append(f"[{timestamp}] '{user}' logged in at unusual hour ({timestamp.hour}:00)")

            # Daily fail threshold
            date_key = timestamp.date()
            if status.endswith("FAILED"):
                if user not in daily_fails:
                    daily_fails[user] = {}
                if date_key not in daily_fails[user]:
                    daily_fails[user][date_key] = 0
                daily_fails[user][date_key] += 1
                if daily_fails[user][date_key] == DAILY_FAIL_LIMIT:
                    suspicious.append(f"[{timestamp}] '{user}' reached {DAILY_FAIL_LIMIT} fails today → possible attack")

            # Brute-force within FAIL_WINDOW
            if status.endswith("FAILED"):
                if user not in fail_times:
                    fail_times[user] = []
                fail_times[user].append(timestamp)
                fail_times[user] = [t for t in fail_times[user] if (timestamp - t).total_seconds() <= FAIL_WINDOW]
                if len(fail_times[user]) == FAIL_THRESHOLD:
                    suspicious.append(f"[{timestamp}] Possible brute-force attack on '{user}' → {FAIL_THRESHOLD} fails in {FAIL_WINDOW}s")

            # Success after fails
            if status.endswith("SUCCESS"):
                if user in fail_times and len(fail_times[user]) >= 3:
                    suspicious.append(f"[{timestamp}] '{user}' logged in successfully after {len(fail_times[user])} failures")
                fail_times[user] = []

        output.insert(tk.END, "\n=== Suspicious Activity Report ===\n")
        if suspicious:
            for s in suspicious:
                output.insert(tk.END, s + "\n")
        else:
            output.insert(tk.END, "No suspicious activity detected.\n")
        output.insert(tk.END, "====================================\n\n")

    def clear_output():
        output.delete(1.0, tk.END)

    # ------------------------------
    # GUI SETUP
    # ------------------------------
    analyzer_root = tk.Toplevel()
    analyzer_root.title("Suspicious Login Analyzer")
    analyzer_root.geometry("700x500")
    analyzer_root.resizable(False, False)

    btn_frame = tk.Frame(analyzer_root)
    btn_frame.pack(pady=10)
    tk.Button(btn_frame, text="Load Logs", width=12, command=load_logs).grid(row=0, column=0, padx=5)
    tk.Button(btn_frame, text="Show Logs", width=12, command=show_raw_logs).grid(row=0, column=1, padx=5)
    tk.Button(btn_frame, text="Analyze", width=12, command=analyze_logs).grid(row=0, column=2, padx=5)
    tk.Button(btn_frame, text="Clear", width=12, command=clear_output).grid(row=0, column=3, padx=5)
    tk.Button(btn_frame, text="Exit", width=12, command=analyzer_root.destroy).grid(row=0, column=4, padx=5)

    output = tk.scrolledtext.ScrolledText(analyzer_root, wrap=tk.WORD, width=80, height=25)
    output.pack(pady=10)
