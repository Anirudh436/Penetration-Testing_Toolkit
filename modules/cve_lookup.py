import requests
import threading
import tkinter as tk
from tkinter import ttk

def fetch_cve_details(cve_id, output_text):
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, f"Fetching details for {cve_id}...\n\n")
    
    def lookup():
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            headers = {"User-Agent": "Mozilla/5.0"}
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    cve_info = vulnerabilities[0].get("cve", {})
                    description = cve_info.get("descriptions", [{}])[0].get("value", "No description available.")
                    severity = vulnerabilities[0].get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("cvssData", {}).get("baseScore", "Unknown")
                    exploitability = vulnerabilities[0].get("cve", {}).get("metrics", {}).get("cvssMetricV2", [{}])[0].get("exploitabilityScore", "Unknown")
                    
                    if output_text.winfo_exists():
                        output_text.after(0, lambda: output_text.insert(tk.END, f"CVE Description:\n{description}\n"))
                        output_text.after(0, lambda: output_text.insert(tk.END, f"Severity Score (CVSS): {severity}\n"))
                        output_text.after(0, lambda: output_text.insert(tk.END, f"Exploitability Score: {exploitability}\n"))
                else:
                    if output_text.winfo_exists():
                        output_text.after(0, lambda: output_text.insert(tk.END, "No details found for the given CVE ID.\n"))
            else:
                if output_text.winfo_exists():
                    output_text.after(0, lambda: output_text.insert(tk.END, f"Failed to fetch data. Status Code: {response.status_code}\n"))
        except requests.RequestException as e:
            if output_text.winfo_exists():
                output_text.after(0, lambda: output_text.insert(tk.END, f"Error fetching CVE details: {e}\n"))
    
    thread = threading.Thread(target=lookup)
    thread.start()

def display_cve_lookup(gui_frame, cve_id):
    for widget in gui_frame.winfo_children():
        widget.destroy()
    
    tk.Label(gui_frame, text="CVE Lookup", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)

    # Immediately start the CVE lookup with the provided CVE ID
    fetch_cve_details(cve_id, output_text)

