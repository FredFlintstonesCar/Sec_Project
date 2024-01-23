import os
import nmap

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def nmap_scan(target):
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-F')  # Fast scan to speed up the process

    result_table = []
    for host in nm.all_hosts():
        hostname = nm[host].hostname() if 'hostname' in nm[host] else ''
        
        addresses = nm[host]['addresses'] if 'addresses' in nm[host] else {}
        mac_address = addresses.get('mac', '')
        
        vendor_info = nm[host]['vendor'] if 'vendor' in nm[host] else {}
        mac_name = vendor_info.get(mac_address, '')

        open_ports = nm[host].all_protocols()
        if 'tcp' in open_ports:
            open_ports = nm[host]['tcp'].keys()
        else:
            open_ports = []

        result_table.append({
            'Hostname': hostname,
            'IP Address': host,
            'Mac Address': mac_address,
            'Mac Address Name': mac_name,
            'Number of Ports Open': len(open_ports)
        })

    return result_table

def print_results(results):
    print("{:<20} {:<15} {:<17} {:<20} {:<25}".format(
        'Mac Address Name', 'Hostname', 'IP Address', 'Mac Address', 'Number of Ports Open'))
    print("="*100)

    for result in results:
        print("{:<20} {:<15} {:<17} {:<20} {:<25}".format(
            result['Mac Address Name'], result['Hostname'], result['IP Address'], result['Mac Address'], result['Number of Ports Open']))

if __name__ == "__main__":
    clear_screen()

    target_network = '192.168.1.0/24'
    scan_results = nmap_scan(target_network)

    print_results(scan_results)
