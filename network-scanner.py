import socket
import ipaddress
import logging
from scapy.all import IP, TCP, sr1

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def check_authorisation(whitelist=None):
    disclaimer = """
            ***************************************************************
            *                     LEGAL DISCLAIMER                      *
            ***************************************************************
            This scanning tool is intended only for systems where you 
            have explicit permission to perform scans. Unauthorised 
            scanning is illegal and unethical. By proceeding, you confirm 
            that you have obtained the necessary authorisation to scan 
            the specified targets.
            
            ***************************************************************

            Do you agree to use this tool responsibly and only on authorized systems? (yes/no): 
            """
    response = input(disclaimer).strip().lower()
    if response != "yes":
        logger.error("Authorization not confirmed. Exiting.")
        exit()

    # Optionally check against a whitelist
    if whitelist:
        target_ip = input("Enter the target IP address for whitelist validation:\n").strip()
        if target_ip not in whitelist:
            logger.error("The target IP is not authorized for scanning according to the whitelist. Exiting.")
            exit()
    
    logger.info("Authorization confirmed. Proceeding with the scan...")

def validate_port(port):
    if port.isdigit() and 1 <= int(port) <= 65535:
        logger.info("The port '%s' is valid", port)
        return port
    else:
        logger.error("The port '%s' is not valid", port)
        return None
       
def validate_ip_address(ip_string):   
    try:
        ip_object = ipaddress.ip_address(ip_string)
        logger.info("The IP address '%s' is valid", ip_object)
        return ip_object
    except ValueError:
        logger.error("The IP address '%s' is not valid", ip_string)
        return None

def get_ip_menu():
    def get_single_ip():
        while True:
            single_ip = input("Enter the targeted IP address:\n")
            single_ip = single_ip.replace(" ", "")
            if validate_ip_address(single_ip):
                break
        
        return [single_ip]

    def get_ip_range():
        while True:
            ip_list = input("Enter a range of IP, supports CIDR notation or state start-end IPs:\n")

            if '/' in ip_list:
                try:
                    ip_check = ip_list.replace(" ","")

                    ip_check = ip_list.split('/')
                    ip_valid = validate_ip_address(ip_check[0].strip())

                    if ip_valid is None:
                        continue

                    ip_range_list = [str(ip) for ip in ipaddress.IPv4Network(ip_list)]

                    return ip_range_list
                except ValueError:
                    logger.error("Invalid CIDR notation. Please try again.")

            elif '-' in ip_list:
                ip_range = ip_list.split('-')
                if len(ip_range) != 2:
                    logger.error("Invalid range format. Use start-end format.")
                    continue
                
                start_part = ip_range[0].replace(" ", "")
                end_part = ip_range[1].replace(" ", "")
                start_ip = validate_ip_address(start_part)
                end_ip = validate_ip_address(end_part)

                if start_ip is None or end_ip is None:
                    logger.error("One or both IP addresses are invalid.")
                    continue

                if int(start_ip) > int(end_ip):
                    logger.error("Start IP must be less than or equal to the End IP.")
                    continue
                    
                ip_range_list = [str(ipaddress.IPv4Address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]

                return ip_range_list

            else:
                print("Invalid input format. Please try again.")

    def get_ip_list():
        while True:
            list_input = input("Enter a list of IP addresses separated by commas or newlines:\n")

            ip_list = [ip.replace(" ", "") for ip in list_input.replace('\n', ',').split(',') if ip.strip()]

            if all(validate_ip_address(ip) for ip in ip_list):
                return ip_list
    
    selection = input("""IP Target Specification:
        1. Single IP: One IP address
        2. Range of IPs: Support CIDR notation or start-end IPs
        3. List of IPs: Accept a comma or newline
        4. Exit\n""")
    
    while selection not in ['1', '2', '3', '4']:
        logger.error("Invalid selection. Please choose a valid option.")
        selection = input("""Target Specification:
        1. Single IP: One IP address
        2. Range of IPs: Support CIDR notation or start/end IPs
        3. List of IPs: Accept a comma or newline
        4. Exit\n""")
    
    if selection == '1':
        return get_single_ip()
    elif selection == '2':
        return get_ip_range()
    elif selection == '3':
        return get_ip_list()
    elif selection == '4':
        exit()

def get_port_menu():
    def get_predefined_port_range():
        return list(range(1, 1025))

    def get_single_port():
        while True:
            single_port = input("Enter the targeted Port:\n")

            single_port = single_port.replace(" ", "")
            if validate_port(single_port):
                return [single_port]

    def get_custom_port_range():
        while True:
            port_list = input("Enter a range of ports, (e.g. 1-1024):\n")

            port_list = port_list.replace(" ", "")

            if '-' in port_list:
                port_range = port_list.split('-')
                if len(port_range) != 2:
                    logger.error("Invalid range format. Use start-end format.")
                    continue
                
                start_port = validate_port(port_range[0].strip())
                end_port = validate_port(port_range[1].strip())

                if start_port is None or end_port is None:
                    logger.error("One or both ports are invalid.")
                    continue

                if int(start_port) > int(end_port):
                    logger.error("Start port must be less than or equal to the End Port.")
                    continue
                    
                port_range_list = []
                for port in range(int(start_port), int(end_port) + 1):
                    port_range_list.append(port)
                
                return [port_range_list]

            else:
                logger.error("Invalid input format. Please try again.")

    def get_list_ports():
        while True:
                list_input = input("Enter a list of Ports separated by commas or newlines:\n")

                port_list = [port.replace(" ", "") for port in list_input.replace('\n', ',').split(',') if port.strip()]

                if all(validate_port(port) for port in port_list):
                    return port_list  
    
    selection = input("""Port Specification:
        1. Predefined Options (1 to 1024)
        2. Single Port
        3. Custom Port Range
        4. List of Ports
        5. Restart
        6. Exit\n""")
    
    while selection not in ['1', '2', '3', '4', '5', '6']:
        logger.error("Invalid selection. Please choose a valid option.")
        selection = input("""Port Specification:
        1. Predefined Options (1 to 1024)
        2. Single Port
        3. Custom Port Range
        4. List of Ports
        5. Restart
        6. Exit\n""")

    if selection == '1':
       return get_predefined_port_range()
    elif selection == '2':
       return get_single_port()
    elif selection == '3':
       return get_custom_port_range()
    elif selection == '4':
        return get_list_ports()
    elif selection == '5':
        return None
    elif selection == '6':
        exit()

def socket_scanning(ips, ports, timeout=0.5):
    open_targets = []

    for ip in ips:
        for port in ports:
            try:
                port = int(port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)

                result = sock.connect_ex((ip, port))

                if result == 0:
                    open_targets.append(f"{ip}:{port}")
                    logger.info("Open: %s:%s", ip, port)
                
                sock.close()
            except Exception as e:
                logger.error("Error scanning %s:%s -> %s", ip, port, e)
    
    return open_targets

def scapy_syn_scan(ip, port, timeout=0.5):
    try:
        ip_packet = IP(dst=ip)
        syn_packet = TCP(dport=int(port), flags='S')

        response = sr1(ip_packet/syn_packet, timeout=timeout, verbose=0)

        if response is None:
            return "filtered"
        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)

            if tcp_layer.flags == 0x12:
                rst_packet = TCP(dport=int(port), flags='R')
                sr1(ip_packet/rst_packet, verbose=0)

                return "open"
            elif tcp_layer.flags == 0x14:
                return "closed"
        
        return "unknown"
    except Exception as e:
        logger.error("Scapy scanning error for %s:%s -> %s", ip, port, e)
        return "error"

def scan_target(ip, port, timeout=0.5):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        result = sock.connect_ex((ip, int(port)))
       
        sock.close()

        if result == 0:
            socket_result = "open"
        else:
            socket_result = "closed"
        
    except Exception as e:
        logger.error("Error scanning %s:%s with socket -> %s", ip, port, e)
        socket_result = "error"

    scapy_result = scapy_syn_scan(ip, port, timeout=timeout * 2)

    return (ip, port, socket_result, scapy_result)

if __name__ == "__main__":
    authorised_ips = []
    check_authorisation(whitelist=authorised_ips)
    
    ips = get_ip_menu()
    ports = get_port_menu()
    while ports is None:
        ports = get_port_menu()

    print("\n--- Running Basic Socket Scan ---")
    open_targets = socket_scanning(ips, ports)
    print("Basic Socket Scan open ports:", open_targets)

    print("\n--- Running Sequential Detailed Scan ---")
    detailed_results = []
    total_scans = len(ips) * len(ports)
    count = 0
    for ip in ips:
        for port in ports:
            count += 1
            logger.info("Scanning %s:%s (%d/%d)...", ip, port, count, total_scans)
            result = scan_target(ip, port)
            detailed_results.append(result)

    detailed_results.sort(key=lambda x: (x[0], x[1]))

    for ip_addr, port, socket_status, scapy_status in detailed_results:
        logger.info("IP: %s, Port: %s -> Socket: %s, Scapy: %s", ip_addr, port, socket_status, scapy_status)
    