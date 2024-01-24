import socket
import subprocess
import tkinter as tk
import os
import re
import psutil

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
        # Run the "route print -4" command and capture the output
        result = subprocess.run(['route', 'print', '-4'], capture_output=True, text=True, check=True)

        # Extract the lines containing the default gateway information
        gateway_lines = re.findall(r'0.0.0.0\s+0.0.0.0\s+(\S+)\s+', result.stdout)

        if gateway_lines:
            # Take the first match (assuming there's only one default gateway)
            default_gateway = gateway_lines[0]
            return default_gateway
        else:
            print("No default gateway found.")
            return None

    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None

# Get the default gateway
default_gateway = get_default_gateway()

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

def nmap_detailed_scan(host):
    result = subprocess.run(['nmap', '-p-', '-sV', '--open', host], capture_output=True, text=True)
    return result

def create_network_map(ip_addresses, default_gateway):
    root = tk.Tk()
    root.title("Home Network Map")

    router_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\router.png").resize((60, 60)))
    pc_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\pc.png").resize((60, 60)))
    comp_img = ImageTk.PhotoImage(Image.open(r"c:\Users\charl\Desktop\comp.png").resize((60, 60)))

    # Add router icon with IP address and hostname
    router_label = tk.Label(root, image=router_img, text=f"{default_gateway}\n{socket.gethostname()}", compound=tk.BOTTOM)
    router_label.grid(row=0, column=len(ip_addresses)//2, padx=20, pady=20)
    
    # Add PC icon with IP address and hostname
    pc_label = tk.Label(root, image=pc_img, text=f"{ip_addresses[0]}\n{socket.gethostname()}", compound=tk.BOTTOM)
    pc_label.grid(row=1, column=len(ip_addresses)//2, padx=20, pady=20)

    # Add other icons with IP address and hostname
    for i, ip in enumerate(ip_addresses[1:]):
        comp_label = tk.Label(root, image=comp_img, text=f"{ip}\n{socket.gethostname()}", compound=tk.BOTTOM)
        comp_label.grid(row=2, column=i, pady=50)

    root.mainloop()

def get_network_info():
    interfaces = psutil.net_if_addrs()
    
    for interface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ipv4_address = addr.address
                mac_address = psutil.net_if_addrs()[interface][0].address

                return interface, ipv4_address, mac_address

def nmap_quick_scan(network):
    #start_time = time()
    result = subprocess.run(['nmap', '-sn', network], capture_output=True, text=True, shell=True)
    #end_time = time()

    return result.stdout

def extract_ip_addresses(quick_scan_result):
    ip_addresses = []
    lines = quick_scan_result.split('\n')

    for line in lines:
        if 'Nmap scan report for' in line:
            ip = line.split()[-1]
            if ip == "(" + ip_address + ")" or ip == "(" + default_gateway + ")":
            #if ip == ipv4_address:    
                ip = []
            else:
                ip_addresses.append(ip)

    return ip_addresses

#Get Network
def get_network(ip):
    return '.'.join(ip.split('.')[:-1]) + '.0/24'

if __name__ == "__main__":
    clear_screen()
    
    network_info = get_network_info()

    if network_info:
        interface, ipv4_address, mac_address = network_info
        print(f"Interface: {interface}")
        print(f"IPv4 Address: {ipv4_address}")
        print(f"MAC Address: {mac_address}")
        #print(f"network info: {network_info}")
        print(f"Hostname: {socket.gethostname()}")
    else:
        print("Unable to retrieve network information.")
    
    network = get_network(ipv4_address)
    print(f"Starting Scan")
    quick_scan_result = nmap_quick_scan(network)
    
    ##print(f"Quick Scan Result: {quick_scan_result}")

    ip_address, gateway = get_ip_and_gateway()
    print(f"IP Address: {ip_address}")
    print(f"Default Gateway: {default_gateway}")

    # For demonstration purposes, we'll create a list of mock IP addresses
    ip_addresses = extract_ip_addresses(quick_scan_result)

    #["192.168.1.2", "192.168.1.3", "192.168.1.4"]
    print(f"IP Address: {ip_addresses}")

    create_network_map(ip_addresses, default_gateway)
