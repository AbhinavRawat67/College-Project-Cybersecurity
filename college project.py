import tkinter as tk
from tkinter import messagebox
import json
import os
import hashlib
import binascii
import datetime
from analyzer import run_analyzer  # Import the analyzer function

CREDENTIALS_FILE = "users.json"
LOG_FILE = "logs.txt"
PBKDF2_ITERATIONS = 100000

def write_log(event):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {event}\n")

def hash_password(password, salt=None, iterations=PBKDF2_ITERATIONS):
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return salt, binascii.hexlify(dk).decode("ascii"), iterations

def verify_password(stored_hash_hex, stored_salt_hex, password_attempt, iterations):
    salt = binascii.unhexlify(stored_salt_hex.encode("ascii"))
    dk_attempt = hashlib.pbkdf2_hmac("sha256", password_attempt.encode("utf-8"), salt, iterations)
    return binascii.hexlify(dk_attempt).decode("ascii") == stored_hash_hex

def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    try:
        with open(CREDENTIALS_FILE, "r") as f:
            return json.load(f)
    except:
        return {}

def save_credentials(users_dict):
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(users_dict, f, indent=2)

def evaluate_strength(pwd, labels, strength_label):
    special_chars = "!@#$%^&*()_+-=<>?/|{}[];:'\",.~`"

    length_ok = len(pwd) >= 8
    lower_ok = any(c.islower() for c in pwd)
    upper_ok = any(c.isupper() for c in pwd)
    digit_ok = any(c.isdigit() for c in pwd)
    spec_ok = any(c in special_chars for c in pwd)

    ok_list = [length_ok, lower_ok, upper_ok, digit_ok, spec_ok]

    # Update colors
    labels["length"].config(fg="green" if length_ok else "red")
    labels["lower"].config(fg="green" if lower_ok else "red")
    labels["upper"].config(fg="green" if upper_ok else "red")
    labels["digit"].config(fg="green" if digit_ok else "red")
    labels["spec"].config(fg="green" if spec_ok else "red")

    score = sum(ok_list)

    if score == 5:
        strength, color = "Very Strong", "green"
    elif score == 4:
        strength, color = "Strong", "darkgreen"
    elif score == 3:
        strength, color = "Medium", "orange"
    elif score == 2:
        strength, color = "Weak", "red"
    else:
        strength, color = "Very Weak", "maroon"

    strength_label.config(text=f"Strength: {strength}", fg=color)


class LoginApp:
    def __init__(self, master):
        self.master = master
        master.title("Simple Login System")
        master.resizable(False, False)
        self.users = load_credentials()

        self.frame_top = tk.Frame(master, padx=10, pady=10)
        self.frame_top.pack()

        # Mode buttons
        self.mode_frame = tk.Frame(self.frame_top)
        self.mode_frame.pack(fill="x", pady=(0,8))
        self.login_btn = tk.Button(self.mode_frame, text="Login", width=12, command=self.show_login)
        self.register_btn = tk.Button(self.mode_frame, text="Register", width=12, command=self.show_register)
        self.analyzer_btn = tk.Button(self.mode_frame, text="Open Analyzer", width=15, command=run_analyzer)
        self.login_btn.grid(row=0, column=0, padx=4)
        self.register_btn.grid(row=0, column=1, padx=4)
        self.analyzer_btn.grid(row=0, column=2, padx=4)

        # Login/Register frames
        self.login_frame = self.build_login_frame(self.frame_top)
        self.register_frame = self.build_register_frame(self.frame_top)
        self.show_login()

    # ----------------------
    # LOGIN FRAME
    # ----------------------
    def build_login_frame(self, parent):
        f = tk.Frame(parent)
        tk.Label(f, text="Username:").grid(row=0, column=0, sticky="e", pady=2)
        self.login_username = tk.Entry(f)
        self.login_username.grid(row=0, column=1, pady=2)
        tk.Label(f, text="Password:").grid(row=1, column=0, sticky="e", pady=2)
        self.login_password = tk.Entry(f, show="*")
        self.login_password.grid(row=1, column=1, pady=2)
        self.login_message = tk.Label(f, text="", fg="red")
        self.login_message.grid(row=2, column=0, columnspan=2, pady=(4,0))
        btn_frame = tk.Frame(f)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Login", width=12, command=self.attempt_login).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Clear", width=8, command=self.clear_login_fields).pack(side="left")
        return f

    # ----------------------
    # REGISTER FRAME
    # ----------------------
    def build_register_frame(self, parent):
        f = tk.Frame(parent)
        tk.Label(f, text="Choose Username:").grid(row=0, column=0, sticky="e", pady=2)
        self.reg_username = tk.Entry(f)
        self.reg_username.grid(row=0, column=1, pady=2)
        tk.Label(f, text="Choose Password:").grid(row=1, column=0, sticky="e", pady=2)
        self.reg_password = tk.Entry(f, show="*")
        self.reg_password.grid(row=1, column=1, pady=2)
        tk.Label(f, text="Confirm Password:").grid(row=2, column=0, sticky="e", pady=2)
        self.reg_password_confirm = tk.Entry(f, show="*")
        self.reg_password_confirm.grid(row=2, column=1, pady=2)
        self.register_message = tk.Label(f, text="", fg="red")
        self.register_message.grid(row=3, column=0, columnspan=2, pady=(4,0))
        btn_frame = tk.Frame(f)
        btn_frame.grid(row=4, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Register", width=12, command=self.attempt_register).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Clear", width=8, command=self.clear_register_fields).pack(side="left")
        return f
    def build_register_frame(self, parent):
        f = tk.Frame(parent)

        tk.Label(f, text="Choose Username:").grid(row=0, column=0, sticky="e", pady=2)
        self.reg_username = tk.Entry(f)
        self.reg_username.grid(row=0, column=1, pady=2)

        tk.Label(f, text="Choose Password:").grid(row=1, column=0, sticky="e", pady=2)
        self.reg_password = tk.Entry(f, show="*")
        self.reg_password.grid(row=1, column=1, pady=2)

        # REAL-TIME STRENGTH LABEL
        self.strength_label = tk.Label(f, text="Strength:", fg="maroon")
        self.strength_label.grid(row=2, column=0, columnspan=2, pady=4)

        # RULE LABELS
        self.rule_labels = {
            "length": tk.Label(f, text="• At least 8 characters", fg="red"),
            "lower": tk.Label(f, text="• Lowercase letter", fg="red"),
            "upper": tk.Label(f, text="• Uppercase letter", fg="red"),
            "digit": tk.Label(f, text="• Number", fg="red"),
            "spec": tk.Label(f, text="• Special character", fg="red")
        }

        r = 3
        for lbl in self.rule_labels.values():
            lbl.grid(row=r, column=0, columnspan=2, sticky="w")
            r += 1

        # BIND KEY RELEASE TO UPDATE STRENGTH
        self.reg_password.bind(
            "<KeyRelease>",
            lambda e: evaluate_strength(self.reg_password.get(), self.rule_labels, self.strength_label)
        )

        tk.Label(f, text="Confirm Password:").grid(row=r, column=0, sticky="e", pady=2)
        self.reg_password_confirm = tk.Entry(f, show="*")
        self.reg_password_confirm.grid(row=r, column=1, pady=2)

        self.register_message = tk.Label(f, text="", fg="red")
        self.register_message.grid(row=r+1, column=0, columnspan=2, pady=(4,0))

        btn_frame = tk.Frame(f)
        btn_frame.grid(row=r+2, column=0, columnspan=2, pady=8)
        tk.Button(btn_frame, text="Register", width=12, command=self.attempt_register).pack(side="left", padx=6)
        tk.Button(btn_frame, text="Clear", width=8, command=self.clear_register_fields).pack(side="left")

        return f


    # ----------------------
    # SHOW/HIDE FRAMES
    # ----------------------
    def show_login(self):
        self.register_frame.pack_forget()
        self.login_frame.pack()
        self.login_message.config(text="")
        self.clear_login_fields()

    def show_register(self):
        self.login_frame.pack_forget()
        self.register_frame.pack()
        self.register_message.config(text="")
        self.clear_register_fields()

    def clear_login_fields(self):
        self.login_username.delete(0, tk.END)
        self.login_password.delete(0, tk.END)
        self.login_message.config(text="")

    def clear_register_fields(self):
        self.reg_username.delete(0, tk.END)
        self.reg_password.delete(0, tk.END)
        self.reg_password_confirm.delete(0, tk.END)
        self.register_message.config(text="")

    # ----------------------
    # REGISTER / LOGIN LOGIC
    # ----------------------
    def attempt_register(self):
        username = self.reg_username.get().strip()
        pw = self.reg_password.get()
        pw_conf = self.reg_password_confirm.get()
        if not username:
            self.register_message.config(text="Username cannot be empty.")
            write_log(f"REGISTER FAILED - username='{username}' reason='username empty'")
            return
        if len(pw) < 6:
            self.register_message.config(text="Password must be at least 6 characters.")
            write_log(f"REGISTER FAILED - username='{username}' reason='password too short'")
            return
        if pw != pw_conf:
            self.register_message.config(text="Passwords do not match.")
            write_log(f"REGISTER FAILED - username='{username}' reason='password mismatch'")
            return
        if username in self.users:
            self.register_message.config(text="Username already exists.")
            write_log(f"REGISTER FAILED - username='{username}' reason='username exists'")
            return
        salt, hash_hex, iterations = hash_password(pw)
        self.users[username] = {
            "salt": binascii.hexlify(salt).decode("ascii"),
            "hash": hash_hex,
            "iterations": iterations
        }
        save_credentials(self.users)
        write_log(f"REGISTER SUCCESS - username='{username}'")
        messagebox.showinfo("Success", f"User '{username}' registered successfully.")
        self.clear_register_fields()
        self.show_login()

    def attempt_login(self):
        username = self.login_username.get().strip()
        pw = self.login_password.get()
        if not username or not pw:
            self.login_message.config(text="Enter both username and password.")
            write_log(f"LOGIN FAILED - username='{username}' reason='missing fields'")
            return
        user_record = self.users.get(username)
        if not user_record:
            self.login_message.config(text="User does not exist.")
            write_log(f"LOGIN FAILED - username='{username}' reason='user does not exist'")
            return
        stored_hash = user_record["hash"]
        stored_salt = user_record["salt"]
        iterations = user_record.get("iterations", PBKDF2_ITERATIONS)
        if verify_password(stored_hash, stored_salt, pw, iterations):
            self.login_message.config(text="", fg="green")
            write_log(f"LOGIN SUCCESS - username='{username}'")
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
            self.clear_login_fields()
        else:
            self.login_message.config(text="Invalid password.", fg="red")
            write_log(f"LOGIN FAILED - username='{username}' reason='wrong password'")

# ----------------------
# MAIN
# ----------------------
def main():
    root = tk.Tk()
    app = LoginApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
