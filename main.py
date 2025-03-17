import tkinter as tk
from tkinter import ttk
from modules.port_scanner import display_port_scanner
from modules.whois_lookup import display_whois_lookup
from modules.subdomain_enum import display_subdomain_enum
from modules.banner_grabbing import display_banner_grabbing
from modules.cve_lookup import display_cve_lookup
from modules.bruteforce import display_brute_force, stop_execution
from modules.packet_sniffer import display_packet_sniffer

class PentestToolkitGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pentest Toolkit")
        self.root.geometry("800x600")
        
        # Create a sidebar for module selection
        self.sidebar = tk.Frame(self.root, width=200, bg="#2C3E50")
        self.sidebar.pack(fill="y", side="left")
        
        # Create a main display area
        self.main_frame = tk.Frame(self.root, bg="#ECF0F1")
        self.main_frame.pack(expand=True, fill="both")
        
        # Add stop button
        self.stop_button = tk.Button(self.sidebar, text="Stop Execution", bg="#E74C3C", fg="white", command=self.stop_execution)
        self.stop_button.pack(fill="x", pady=10, padx=5)
        
        # Add module buttons to the sidebar
        self.modules = {
            "Port Scanning": self.show_port_scanner,
            "WHOIS Lookup": self.show_whois_lookup,
            "Subdomain Enum": self.show_subdomain_enum,
            "Banner Grabbing": self.show_banner_grabbing,
            "CVE Lookup": self.show_cve_lookup,
            "Brute Force": self.show_brute_force,
            "Packet Sniffer": self.show_packet_sniffer,
        }
        
        for module_name, command in self.modules.items():
            btn = tk.Button(self.sidebar, text=module_name, bg="#34495E", fg="white", command=command)
            btn.pack(fill="x", pady=2, padx=5)
        
        # Default content
        self.show_home()
    
    def clear_main_frame(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
    
    def create_scrollable_text(self):
        text_widget = tk.Text(self.main_frame, height=15, width=80)
        text_widget.pack(pady=5)
        return text_widget
    
    def show_home(self):
        self.clear_main_frame()
        label = tk.Label(self.main_frame, text="Welcome to the Pentest Toolkit", font=("Arial", 16), bg="#ECF0F1")
        label.pack(pady=20)
    
    def add_start_button(self, command):
        start_button = tk.Button(self.main_frame, text="Start", command=command)
        start_button.pack(pady=5)
    
    def stop_execution(self):
        stop_execution()
    
    def show_port_scanner(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Target URL:").pack()
        entry = tk.Entry(self.main_frame, width=40)
        entry.pack(pady=5)
        output_text = self.create_scrollable_text()
        self.add_start_button(lambda: display_port_scanner(self.main_frame, entry.get()))

    def show_whois_lookup(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Domain:").pack()
        entry = tk.Entry(self.main_frame, width=40)
        entry.pack(pady=5)
        output_text = self.create_scrollable_text()
        self.add_start_button(lambda: display_whois_lookup(self.main_frame, entry.get()))

    def show_subdomain_enum(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Target Domain:").pack()
        entry = tk.Entry(self.main_frame, width=40)
        entry.pack(pady=5)
        output_text = self.create_scrollable_text()
        self.add_start_button(lambda: display_subdomain_enum(self.main_frame, entry.get()))

    def show_banner_grabbing(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="Target IP:").pack()
        entry = tk.Entry(self.main_frame, width=40)
        entry.pack(pady=5)
        output_text = self.create_scrollable_text()
        self.add_start_button(lambda: display_banner_grabbing(self.main_frame, entry.get()))

    def show_brute_force(self):
        self.clear_main_frame()
        display_brute_force(self.main_frame)
    
    def show_cve_lookup(self):
        self.clear_main_frame()
        tk.Label(self.main_frame, text="CVE ID:").pack()
        entry = tk.Entry(self.main_frame, width=40)
        entry.pack(pady=5)
        output_text = self.create_scrollable_text()
        self.add_start_button(lambda: display_cve_lookup(self.main_frame, entry.get()))
    
    def show_packet_sniffer(self):
        self.clear_main_frame()
        display_packet_sniffer(self.main_frame)  # Correctly calls the function from packet_sniffer.py

if __name__ == "__main__":
    root = tk.Tk()
    app = PentestToolkitGUI(root)
    root.mainloop()
