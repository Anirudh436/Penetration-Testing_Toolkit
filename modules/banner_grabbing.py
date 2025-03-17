import socket
import threading
import tkinter as tk
from tkinter import ttk

def grab_banner(target, port, output_text):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect((target, port))
            s.sendall(b"\r\n")
            banner = s.recv(1024).decode().strip()
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, f"Port {port}: {banner}\n"))
    except Exception:
        if output_text.winfo_exists():
            output_text.after(0, lambda: output_text.insert(tk.END, f"Port {port}: No banner received\n"))

def perform_banner_grabbing(target, ports, output_text):
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Grabbing banners for {target}...\n\n")
    
    def scan():
        for port in ports:
            thread = threading.Thread(target=grab_banner, args=(target, port, output_text))
            thread.start()
            thread.join()
        if output_text.winfo_exists():
            output_text.after(0, lambda: output_text.insert(tk.END, "\nBanner grabbing completed.\n"))
    
    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

def display_banner_grabbing(gui_frame, target):
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="Banner Grabbing", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)

    # Immediately start banner grabbing with the provided target
    perform_banner_grabbing(target, [21, 22, 25, 80, 110, 143, 443, 587], output_text)

