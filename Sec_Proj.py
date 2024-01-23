import socket
import subprocess
import tkinter as tk
import os

from PIL import Image, ImageTk

def clear_screen():
    # Clear screen for Windows
    if os.name == 'nt':
        _ = os.system('cls')
    # Clear screen for other operating systems (Linux, macOS)
    else:
        _ = os.system('clear')

def get_default_gateway():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 1))  # Connect to a Google DNS server
            default_gateway = s.getsockname()[0]
        return default_gateway
    except Exception as e:
        print(f"Error getting default gateway: {e}")
        return None

def get_ip_and_gateway():
    host_name = socket.gethostname()
    ip_address = socket.gethostbyname(host_name)
    
    gateway = None
    try:
        output = subprocess.check_output(['ipconfig'], universal_newlines=True)
        lines = output.split('\n')
        ip_config_lines = [line.strip() for line in lines if line.strip()]
        
        # Assuming the second entry in ipconfig output contains the default gateway
        if len(ip_config_lines) > 1:
            gateway = ip_config_lines[1].split(':')[-1].strip()
    except subprocess.CalledProcessError:
        pass

    return ip_address, gateway

def nmap_quick_scan(network):
    start_time = time()
    result = subprocess.run(['nmap', '-sn', network], capture_output=True, text=True)
    end_time = time()

    return result

def create_network_map(ip_addresses, gateway):
    root = tk.Tk()
    root.title("Home Network Map")

    router_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\router.png").resize((60, 60)))
    pc_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\pc.png").resize((60, 60)))
    comp_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\comp.png").resize((60, 60)))

    # Add router icon with IP address and hostname
    router_label = tk.Label(root, image=router_img, text=f"{gateway}\n{socket.gethostname()}", compound=tk.BOTTOM)
    router_label.grid(row=0, column=len(ip_addresses)//2, padx=20, pady=20)
    
    # Add PC icon with IP address and hostname
    pc_label = tk.Label(root, image=pc_img, text=f"{ip_addresses[0]}\n{socket.gethostname()}", compound=tk.BOTTOM)
    pc_label.grid(row=1, column=len(ip_addresses)//2, padx=20, pady=20)

    # Add other icons with IP address and hostname
    for i, ip in enumerate(ip_addresses[1:]):
        comp_label = tk.Label(root, image=comp_img, text=f"{ip}\n{socket.gethostname()}", compound=tk.BOTTOM)
        comp_label.grid(row=2, column=i, pady=50)

    root.mainloop()

if __name__ == "__main__":
    clear_screen()
    
    ip_address, gateway = get_ip_and_gateway()
    print(f"IP Address: {ip_address}")
    print(f"Default Gateway: {get_default_gateway()}")

    # For demonstration purposes, we'll create a list of mock IP addresses
    ip_addresses = ["192.168.1.2", "192.168.1.3", "192.168.1.4"]

    create_network_map(ip_addresses, get_default_gateway())
