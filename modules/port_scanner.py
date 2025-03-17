import socket
import threading
import tkinter as tk
from tkinter import ttk

def scan_port(target, port, results, output_text):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            if result == 0:
                results.append(port)
                if output_text.winfo_exists():
                    output_text.after(0, lambda: output_text.insert(tk.END, f"Port {port} is open\n"))
    except Exception as e:
        pass

def port_scanner(target, port_range=(1, 1024), threads=50, output_text=None):
    open_ports = []
    threads_list = []
    
    if output_text.winfo_exists():
        output_text.after(0, lambda: output_text.insert(tk.END, f"Scanning {target} for open ports in range {port_range[0]}-{port_range[1]}...\n"))
    
    def scan():
        for port in range(port_range[0], port_range[1] + 1):
            thread = threading.Thread(target=scan_port, args=(target, port, open_ports, output_text))
            threads_list.append(thread)
            thread.start()
            
            if len(threads_list) >= threads:
                for t in threads_list:
                    t.join()
                threads_list.clear()
        
        for t in threads_list:
            t.join()
        
        if output_text.winfo_exists():
            output_text.after(0, lambda: output_text.insert(tk.END, f"Scan complete. Open ports: {open_ports}\n" if open_ports else "No open ports found.\n"))
    
    scan_thread = threading.Thread(target=scan)
    scan_thread.start()

def run_port_scanner(target, output_text):
    target = target.strip()  # Ensure target is a clean string
    output_text.delete(1.0, tk.END)
    if not target:
        output_text.insert(tk.END, "Please enter a target URL or IP.\n")
        return
    try:
        target_ip = socket.gethostbyname(target)
        output_text.insert(tk.END, f"Resolved {target} to {target_ip}\n")
        scan_thread = threading.Thread(target=port_scanner, args=(target_ip, (1, 1024), 50, output_text))
        scan_thread.start()
    except socket.gaierror:
        output_text.insert(tk.END, "Invalid hostname. Please enter a valid URL or IP.\n")


# Integration with main.py GUI
def display_port_scanner(gui_frame, target):
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="Port Scanner", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)
    
    # Immediately start scanning using the provided target
    run_port_scanner(target, output_text)
