from scapy.all import sniff
import threading
import tkinter as tk

stop_sniffing = threading.Event()

def packet_sniffer(output_text):
    stop_sniffing.clear()

    def process_packet(packet):
        if stop_sniffing.is_set():
            return  # Stop sniffing when requested
        if output_text.winfo_exists():
            output_text.after(0, lambda: output_text.insert(tk.END, f"\nPacket: {packet.summary()}\n"))

    sniff(prn=process_packet, store=False, stop_filter=lambda p: stop_sniffing.is_set())

def stop_sniffer():
    stop_sniffing.set()

def display_packet_sniffer(gui_frame):
    for widget in gui_frame.winfo_children():
        widget.destroy()

    tk.Label(gui_frame, text="Packet Sniffer", font=("Arial", 14)).pack(pady=10)
    output_text = tk.Text(gui_frame, height=15, width=80)
    output_text.pack(pady=5)

    start_button = tk.Button(gui_frame, text="Start Sniffing", command=lambda: threading.Thread(target=packet_sniffer, args=(output_text,), daemon=True).start())
    start_button.pack(pady=5)

    stop_button = tk.Button(gui_frame, text="Stop Sniffing", command=stop_sniffer)
    stop_button.pack(pady=5)
