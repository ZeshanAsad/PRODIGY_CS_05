from tkinter import *
from tkinter.scrolledtext import ScrolledText
from scapy.all import *
import threading
from PIL import Image, ImageTk
import os
import base64
sniff_comp = base64.b64decode("VGhpcyBjb2RlIGlzIGNyZWF0ZWQgYnkgWmVlc2hhbiBBc2Fk").decode("utf-8")

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        log_text.insert(END, f"IP Source: {ip_src} --> IP Destination: {ip_dst} | Protocol: {protocol}\n")
        
        if packet.haslayer(TCP):
            payload_TCP = packet[TCP].payload
            log_text.insert(END, "TCP Payload data:\n")
            log_text.insert(END, f"{payload_TCP}\n")

        if packet.haslayer(UDP):
            payload_UDP = packet[UDP].payload
            log_text.insert(END, "UDP Payload data:\n")
            log_text.insert(END, f"{payload_UDP}\n")

def start_sniffing():
    log_text.delete(1.0, END)
    log_text.insert(END, "Sniffing Started\n")
    t = threading.Thread(target=sniff_packets)
    t.start()

def sniff_packets():
    sniff(prn=packet_callback, store=0)

root = Tk()
root.title("Packet Sniffer")

dir_path = os.path.dirname(os.path.realpath(__file__))

image_path = os.path.join(dir_path, "sniff.png")


background_image = Image.open(image_path)

width, height = root.winfo_screenwidth(), root.winfo_screenheight()
background_image.thumbnail((width, height))
background_photo = ImageTk.PhotoImage(background_image)
background_label = Label(root, image=background_photo)
background_label.place(x=0, y=0, relwidth=1, relheight=1)

imp_func = Label(root, text=sniff_comp, font=("Helvetica", 8), fg="white", bg="black")
imp_func.pack(side=BOTTOM)


start_button = Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)

log_text = ScrolledText(root, width=60, height=20)
log_text.pack(padx=10, pady=10)

root.mainloop()
