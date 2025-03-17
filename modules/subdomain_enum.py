import socket
import requests
import threading
import tkinter as tk
from tkinter import ttk

def enumerate_subdomains(domain, output_text):
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching subdomains for {domain} from crt.sh...\n\n")
    
    def fetch_subdomains():
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {"User-Agent": "Mozilla/5.0"}
            
            for _ in range(3):  # Retry up to 3 times
                response = requests.get(url, headers=headers, timeout=20)
                
                if response.status_code == 200:
                    break  # Successful response, exit loop
            else:
                if output_text.winfo_exists():
                    output_text.after(0, lambda: output_text.insert(tk.END, "Failed after multiple attempts.\n"))
                return

            data = response.json()
            subdomains = {entry["name_value"] for entry in data if "name_value" in entry}

            if not subdomains:
                output_text.after(0, lambda: output_text.insert(tk.END, "No subdomains found.\n"))
            else:
                for sub in sorted(subdomains):
                    try:
                        ip = socket.gethostbyname(sub)
                        output_text.after(0, lambda: output_text.insert(tk.END, f"{sub} -> {ip}\n"))
                    except socket.gaierror:
                        output_text.after(0, lambda: output_text.insert(tk.END, f"{sub} -> Could not resolve\n"))

        except requests.RequestException as e:
            output_text.after(0, lambda: output_text.insert(tk.END, f"Error fetching subdomains: {e}\n"))

    
    # Run in a separate thread to prevent GUI freezing
    thread = threading.Thread(target=fetch_subdomains)
    thread.start()

def display_subdomain_enum(gui_frame, domain):
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="Subdomain Enumeration", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)
    
    # Immediately start enumeration using the provided domain
    enumerate_subdomains(domain, output_text)

