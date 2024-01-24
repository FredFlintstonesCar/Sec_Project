import subprocess
import os

def clear_screen():
    if os.name == 'nt':  # Check if the operating system is Windows
        os.system('cls')
    else:
        os.system('clear')



def nmap_scan(ip_range):
    command = f'nmap -sn {ip_range}'  # -sn option for host discovery (ping scan)
    result = subprocess.run(command, capture_output=True, text=True, shell=True)

    if result.returncode == 0:
        return result.stdout
    else:
        return f"Error: {result.stderr}"

def extract_ip_addresses(scan_result):
    ip_addresses = []
    lines = scan_result.split('\n')

    for line in lines:
        if 'Nmap scan report for' in line:
            ip = line.split()[-1]
            ip_addresses.append(ip)

    return ip_addresses

def main():
    clear_screen()
    ip_range = '192.168.1.0/24'
    
    print(f"Scanning IP range: {ip_range}\n")
    
    scan_result = nmap_scan(ip_range)
    
    ip_addresses = extract_ip_addresses(scan_result)
    
    print(f"IP's {scan_result}")
    print(f"IP's {ip_addresses}")

    print("IP Addresses found:")
    for ip in ip_addresses:
        print(ip)

if __name__ == "__main__":
    main()