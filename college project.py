import tkinter as tk
from tkinter import messagebox
import json, os, hashlib, binascii, datetime

# Try to import the analyzer; if not present provide a safe fallback
try:
    from analyzer import run_analyzer  # Analyzer function
except Exception:
    def run_analyzer():
        messagebox.showinfo("Analyzer", "Analyzer module not available.")

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
    except Exception:
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

    labels["length"].config(fg="green" if length_ok else "red")
    labels["lower"].config(fg="green" if lower_ok else "red")
    labels["upper"].config(fg="green" if upper_ok else "red")
    labels["digit"].config(fg="green" if digit_ok else "red")
    labels["spec"].config(fg="green" if spec_ok else "red")

    score = sum([length_ok, lower_ok, upper_ok, digit_ok, spec_ok])
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

def main():
    users = load_credentials()
    root = tk.Tk()
    root.title("Simple Login System")
    root.resizable(False, False)

    # Top-level container
    top_frame = tk.Frame(root, padx=10, pady=10)
    top_frame.pack()

    # Header frame for the buttons (use pack inside header)
    header_frame = tk.Frame(top_frame)
    header_frame.pack(fill="x", pady=(0, 8))

    # Content frame for login/register (also pack-managed)
    content_frame = tk.Frame(top_frame)
    content_frame.pack()

    # Create login and register frames as children of content_frame
    login_frame = tk.Frame(content_frame)
    register_frame = tk.Frame(content_frame)

    # ----------------------
    # LOGIN FRAME (uses grid inside login_frame)
    # ----------------------
    tk.Label(login_frame, text="Username:").grid(row=0, column=0, sticky="e", pady=2)
    login_username = tk.Entry(login_frame)
    login_username.grid(row=0, column=1, pady=2)
    tk.Label(login_frame, text="Password:").grid(row=1, column=0, sticky="e", pady=2)
    login_password = tk.Entry(login_frame, show="*")
    login_password.grid(row=1, column=1, pady=2)
    login_message = tk.Label(login_frame, text="", fg="red")
    login_message.grid(row=2, column=0, columnspan=2, pady=(4,0))

    def clear_login_fields():
        login_username.delete(0, tk.END)
        login_password.delete(0, tk.END)
        login_message.config(text="")

    def attempt_login():
        username = login_username.get().strip()
        pw = login_password.get()
        if not username or not pw:
            login_message.config(text="Enter both username and password.")
            write_log(f"LOGIN FAILED - username='{username}' reason='missing fields'")
            return
        user_record = users.get(username)
        if not user_record:
            login_message.config(text="User does not exist.")
            write_log(f"LOGIN FAILED - username='{username}' reason='user does not exist'")
            return
        if verify_password(user_record["hash"], user_record["salt"], pw, user_record.get("iterations", PBKDF2_ITERATIONS)):
            login_message.config(text="", fg="green")
            write_log(f"LOGIN SUCCESS - username='{username}'")
            messagebox.showinfo("Login Successful", f"Welcome, {username}!")
            clear_login_fields()
        else:
            login_message.config(text="Invalid password.", fg="red")
            write_log(f"LOGIN FAILED - username='{username}' reason='wrong password'")

    tk.Button(login_frame, text="Login", width=12, command=attempt_login).grid(row=3, column=0, pady=8)
    tk.Button(login_frame, text="Clear", width=8, command=clear_login_fields).grid(row=3, column=1)

    # ----------------------
    # REGISTER FRAME (uses grid inside register_frame)
    # ----------------------
    tk.Label(register_frame, text="Choose Username:").grid(row=0, column=0, sticky="e", pady=2)
    reg_username = tk.Entry(register_frame)
    reg_username.grid(row=0, column=1, pady=2)
    tk.Label(register_frame, text="Choose Password:").grid(row=1, column=0, sticky="e", pady=2)
    reg_password = tk.Entry(register_frame, show="*")
    reg_password.grid(row=1, column=1, pady=2)

    strength_label = tk.Label(register_frame, text="Strength:", fg="maroon")
    strength_label.grid(row=2, column=0, columnspan=2, pady=4)

    rule_labels = {
        "length": tk.Label(register_frame, text="• At least 8 characters", fg="red"),
        "lower": tk.Label(register_frame, text="• Lowercase letter", fg="red"),
        "upper": tk.Label(register_frame, text="• Uppercase letter", fg="red"),
        "digit": tk.Label(register_frame, text="• Number", fg="red"),
        "spec": tk.Label(register_frame, text="• Special character", fg="red")
    }

    r = 3
    for lbl in rule_labels.values():
        lbl.grid(row=r, column=0, columnspan=2, sticky="w")
        r += 1

    tk.Label(register_frame, text="Confirm Password:").grid(row=r, column=0, sticky="e", pady=2)
    reg_password_confirm = tk.Entry(register_frame, show="*")
    reg_password_confirm.grid(row=r, column=1, pady=2)

    register_message = tk.Label(register_frame, text="", fg="red")
    register_message.grid(row=r+1, column=0, columnspan=2, pady=(4,0))

    def clear_register_fields():
        reg_username.delete(0, tk.END)
        reg_password.delete(0, tk.END)
        reg_password_confirm.delete(0, tk.END)
        register_message.config(text="")

    def attempt_register():
        username = reg_username.get().strip()
        pw = reg_password.get()
        pw_conf = reg_password_confirm.get()
        if not username:
            register_message.config(text="Username cannot be empty.")
            write_log(f"REGISTER FAILED - username='{username}' reason='username empty'")
            return
        if len(pw) < 6:
            register_message.config(text="Password must be at least 6 characters.")
            write_log(f"REGISTER FAILED - username='{username}' reason='password too short'")
            return
        if pw != pw_conf:
            register_message.config(text="Passwords do not match.")
            write_log(f"REGISTER FAILED - username='{username}' reason='password mismatch'")
            return
        if username in users:
            register_message.config(text="Username already exists.")
            write_log(f"REGISTER FAILED - username='{username}' reason='username exists'")
            return
        salt, hash_hex, iterations = hash_password(pw)
        users[username] = {"salt": binascii.hexlify(salt).decode("ascii"), "hash": hash_hex, "iterations": iterations}
        save_credentials(users)
        write_log(f"REGISTER SUCCESS - username='{username}'")
        messagebox.showinfo("Success", f"User '{username}' registered successfully.")
        clear_register_fields()
        show_login()

    reg_password.bind("<KeyRelease>", lambda e: evaluate_strength(reg_password.get(), rule_labels, strength_label))

    tk.Button(register_frame, text="Register", width=12, command=attempt_register).grid(row=r+2, column=0, pady=8)
    tk.Button(register_frame, text="Clear", width=8, command=clear_register_fields).grid(row=r+2, column=1)

    # Frame switch functions
    def show_login():
        register_frame.pack_forget()
        login_frame.pack()
        login_message.config(text="")
        clear_login_fields()

    def show_register():
        login_frame.pack_forget()
        register_frame.pack()
        register_message.config(text="")
        clear_register_fields()

    # ----------------------
    # Top buttons go into header_frame (use pack, so no mixing in top_frame)
    # ----------------------
    tk.Button(header_frame, text="Login", width=12, command=show_login).pack(side="left", padx=4)
    tk.Button(header_frame, text="Register", width=12, command=show_register).pack(side="left", padx=4)
    tk.Button(header_frame, text="Open Analyzer", width=15, command=run_analyzer).pack(side="left", padx=4)

    # show default frame
    show_login()
    root.mainloop()

if __name__ == "__main__":
    main()
