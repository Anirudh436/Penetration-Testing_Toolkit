import socket
import whois
import threading
import tkinter as tk
from tkinter import ttk

def perform_whois_lookup(target, output_text):
    output_text.delete(1.0, tk.END)
    
    def fetch_whois():
        try:
            target_ip = socket.gethostbyname(target)
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, f"Resolved {target} to {target_ip}\n\n"))
            
            w = whois.whois(target)
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, "WHOIS Information:\n"))
                output_text.after(0, lambda: output_text.insert(tk.END, str(w)))
        except socket.gaierror:
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, "Invalid hostname. Please enter a valid domain or IP.\n"))
        except Exception as e:
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, f"Error: {e}\n"))
    
    # Run in a separate thread to prevent GUI freezing
    thread = threading.Thread(target=fetch_whois)
    thread.start()

def display_whois_lookup(gui_frame, domain):
    # Clear the GUI frame
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="WHOIS Lookup", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)
    
    # Immediately perform the WHOIS lookup with the provided domain
    perform_whois_lookup(domain, output_text)
