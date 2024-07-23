import sys
import paramiko
from cryptography.fernet import Fernet
import json
import time
import re
import smtplib
from email.mime.text import MIMEText
import configparser

def load_key():
    return open("Huawei_Blackholing.key", "rb").read()

def decrypt_credentials():
    key = load_key()
    f = Fernet(key)
    with open("Huawei_Blackholing.enc", "rb") as enc_file:
        encrypted_credentials = enc_file.read()
    decrypted_credentials = json.loads(f.decrypt(encrypted_credentials).decode())
    return decrypted_credentials

def load_config():
    config = configparser.ConfigParser()
    config.read("Huawei_Blackholing.conf")
    return config

def generate_blackhole_commands(ipv4_list, ipv6_list, clean_all=False, list_only=False, add_ip=None, remove_ip=None):
    commands = ["system"]
    if list_only:
        commands.append("display current-configuration | include BLACKHOLE-OUT")
        commands.append("display current-configuration | include tag 666")
    elif clean_all:
        for ipv4, index in ipv4_list:
            if index != '10':  # Skip index 10
                commands.append(f"undo ip ip-prefix BLACKHOLE-OUT index {index}")
                commands.append(f"undo ip route-static {ipv4} 255.255.255.255 NULL0")
        for ipv6, index in ipv6_list:
            if index != '10':  # Skip index 10
                commands.append(f"undo ip ipv6-prefix BLACKHOLE-OUT index {index}")
                commands.append(f"undo ipv6 route-static {ipv6} 128 NULL0")
        commands.append("commit")
    elif add_ip:
        if ':' in add_ip[0]:  # IPv6 address
            ipv6, index = add_ip
            commands.append(f"ip ipv6-prefix BLACKHOLE-OUT index {index} permit {ipv6} 128")
            commands.append(f"ipv6 route-static {ipv6} 128 NULL0 tag 666")
        else:  # IPv4 address
            ipv4, index = add_ip
            commands.append(f"ip ip-prefix BLACKHOLE-OUT index {index} permit {ipv4} 32")
            commands.append(f"ip route-static {ipv4} 255.255.255.255 NULL0 tag 666")
        commands.append("commit")
    elif remove_ip:
        if ':' in remove_ip[0]:  # IPv6 address
            ipv6, index = remove_ip
            commands.append(f"undo ip ipv6-prefix BLACKHOLE-OUT index {index}")
            commands.append(f"undo ipv6 route-static {ipv6} 128 NULL0")
        else:  # IPv4 address
            ipv4, index = remove_ip
            commands.append(f"undo ip ip-prefix BLACKHOLE-OUT index {index}")
            commands.append(f"undo ip route-static {ipv4} 255.255.255.255 NULL0")
        commands.append("commit")
    else:
        index = 20
        for ipv4 in ipv4_list:
            commands.append(f"ip ip-prefix BLACKHOLE-OUT index {index} permit {ipv4} 32")
            commands.append(f"ip route-static {ipv4} 255.255.255.255 NULL0 tag 666")
            index += 10
        index = 20
        for ipv6 in ipv6_list:
            commands.append(f"ip ipv6-prefix BLACKHOLE-OUT index {index} permit {ipv6} 128")
            commands.append(f"ipv6 route-static {ipv6} 128 NULL0 tag 666")
            index += 10

    return commands

def print_help():
    help_text = """
    Usage: python Huawei_Blackholing.py [options] [IP addresses]
    
    Options:
      clean-all      Removes all blackhole routes and IP prefixes.
      list           Lists the current blackhole IP prefixes and routes with tag 666.
      add            Adds a new IP address to the blackhole configuration.
      remove         Removes an IP address from the blackhole configuration.
      help           Shows this help message.
    """
    print(help_text)

def execute_ssh_commands(commands):
    credentials = decrypt_credentials()
    hostname = credentials.get('router_ip')
    username = credentials.get('username')
    password = credentials.get('password')

    if not all([hostname, username, password]):
        print("Missing required credentials.")
        sys.exit(1)
    
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    client.connect(hostname, username=username, password=password)
    
    shell = client.invoke_shell()
    time.sleep(1)
    
    output = ""
    for command in commands:
        shell.send(command + '\n')
        time.sleep(2)
        while not shell.recv_ready():
            time.sleep(1)
        command_output = shell.recv(9999).decode('utf-8')
        output += command_output
    
    client.close()
    return output

def parse_blackhole_configuration(output):
    ipv4_prefix_pattern = re.compile(r'ip ip-prefix BLACKHOLE-OUT index (\d+) permit (\d+\.\d+\.\d+\.\d+)')
    ipv6_prefix_pattern = re.compile(r'ip ipv6-prefix BLACKHOLE-OUT index (\d+) permit ([\da-fA-F:]+)')
    ipv4_route_pattern = re.compile(r'ip route-static (\d+\.\d+\.\d+\.\d+) 255\.255\.255\.255 NULL0 tag 666( no-advertise description Da abilitare in caso di blackholing \(DO NOT REMOVE!\))?')
    ipv6_route_pattern = re.compile(r'ipv6 route-static ([\da-fA-F:]+) 128 NULL0 tag 666( no-advertise description Da abilitare in caso di blackholing \(DO NOT REMOVE!\))?')

    ipv4_prefixes = ipv4_prefix_pattern.findall(output)
    ipv6_prefixes = ipv6_prefix_pattern.findall(output)
    ipv4_routes = ipv4_route_pattern.findall(output)
    ipv6_routes = ipv6_route_pattern.findall(output)

    ipv4_excluded_routes = [match[0] for match in ipv4_routes if match[1]]
    ipv6_excluded_routes = [match[0] for match in ipv6_routes if match[1]]

    ipv4_prefixes = [(index, ip) for index, ip in ipv4_prefixes if ip not in ipv4_excluded_routes]
    ipv6_prefixes = [(index, ip) for index, ip in ipv6_prefixes if ip not in ipv6_excluded_routes]
    ipv4_routes = [ip for ip in ipv4_routes if not ip[1]]
    ipv6_routes = [ip for ip in ipv6_routes if not ip[1]]

    return ipv4_prefixes, ipv6_prefixes, [r[0] for r in ipv4_routes], [r[0] for r in ipv6_routes]

def find_max_index(ipv4_prefixes, ipv6_prefixes):
    max_index = 20
    for index, _ in ipv4_prefixes + ipv6_prefixes:
        index_int = int(index)
        if index_int > max_index:
            max_index = index_int
    return max_index

def send_email(log):
    config = load_config()
    signature = "\n\nGOLINE SA\nSecurity Operations Center"
    msg = MIMEText(log + signature)
    msg['Subject'] = 'IP Blackholing operation in progress...'
    msg['From'] = config['Main']['sender']
    msg['To'] = config['Main']['recipient']

    with smtplib.SMTP(config['Main']['smtp_server'], config['Main']['port']) as server:
        server.sendmail(config['Main']['sender'], config['Main']['recipient'], msg.as_string())

def main():
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    option = sys.argv[1].lower()
    ip_addresses = sys.argv[2:]

    ipv4_list = [ip for ip in ip_addresses if ":" not in ip]
    ipv6_list = [ip for ip in ip_addresses if ":" in ip]

    valid_options = {"clean-all", "list", "add", "remove", "help"}

    if option not in valid_options:
        print(f"Invalid option: {option}")
        print_help()
        sys.exit(1)

    clean_all = option == "clean-all"
    list_only = option == "list"
    add_ip = option == "add"
    remove_ip = option == "remove"

    log = ""

    if list_only:
        commands = generate_blackhole_commands(ipv4_list, ipv6_list, list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)
        log += "Listing current blackhole IP prefixes and routes with tag 666...\n"
        if ipv4_prefixes:
            log += "IPv4 Prefixes in BLACKHOLE-OUT:\n"
            for index, prefix in ipv4_prefixes:
                log += f"{prefix} (index {index})\n"
        else:
            log += "IPv4 Prefixes in BLACKHOLE-OUT: No IPv4 found.\n"
        
        if ipv6_prefixes:
            log += "\nIPv6 Prefixes in BLACKHOLE-OUT:\n"
            for index, prefix in ipv6_prefixes:
                log += f"{prefix} (index {index})\n"
        else:
            log += "IPv6 Prefixes in BLACKHOLE-OUT: No IPv6 found.\n"
        
        if ipv4_routes:
            log += "\nIPv4 Routes with tag 666:\n"
            for route in ipv4_routes:
                log += f"{route}\n"
        else:
            log += "IPv4 Routes with tag 666: no IPv4 route found.\n"
        
        if ipv6_routes:
            log += "\nIPv6 Routes with tag 666:\n"
            for route in ipv6_routes:
                log += f"{route}\n"
        else:
            log += "IPv6 Routes with tag 666: no IPv6 route found.\n"

    elif add_ip:
        new_ip = ip_addresses[0]  # Assuming only one IP is passed for adding
        commands = generate_blackhole_commands(ipv4_list, ipv6_list, list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        # Check if the IP already exists
        if any(ip == new_ip for _, ip in ipv4_prefixes + ipv6_prefixes):
            log += f"IP {new_ip} already exists in BLACKHOLE-OUT\n"
            sys.exit(1)
        if new_ip in ipv4_routes + ipv6_routes:
            log += f"IP {new_ip} already exists as a route with tag 666\n"
            sys.exit(1)

        # Find the highest index and increment by 10
        max_index = find_max_index(ipv4_prefixes, ipv6_prefixes)
        new_index = max_index + 10

        # Add the new IP
        if ':' in new_ip:
            commands = generate_blackhole_commands(ipv4_list, ipv6_list, add_ip=(new_ip, new_index))
        else:
            commands = generate_blackhole_commands(ipv4_list, ipv6_list, add_ip=(new_ip, new_index))
        output = execute_ssh_commands(commands)

        # Verify the addition
        commands = generate_blackhole_commands(ipv4_list, ipv6_list, list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        log += "Verification of addition...\n"
        if any(ip == new_ip for _, ip in ipv4_prefixes + ipv6_prefixes):
            log += f"IP prefix {new_ip} added successfully\n"
        else:
            log += f"Failed to add IP prefix {new_ip}\n"

        if new_ip in ipv4_routes + ipv6_routes:
            log += f"IP route {new_ip} added successfully\n"
        else:
            log += f"Failed to add IP route {new_ip}\n"
    elif remove_ip:
        del_ip = ip_addresses[0]  # Assuming only one IP is passed for removing
        commands = generate_blackhole_commands(ipv4_list, ipv6_list, list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        # Check if the IP exists
        index_to_remove = None
        for index, ip in ipv4_prefixes + ipv6_prefixes:
            if ip == del_ip:
                index_to_remove = index
                break

        if not index_to_remove:
            log += f"IP {del_ip} not found in BLACKHOLE-OUT\n"
            sys.exit(1)
        if del_ip not in ipv4_routes + ipv6_routes:
            log += f"IP {del_ip} not found as a route with tag 666\n"
            sys.exit(1)

        # Remove the IP
        if ':' in del_ip:
            commands = generate_blackhole_commands(ipv4_list, ipv6_list, remove_ip=(del_ip, index_to_remove))
        else:
            commands = generate_blackhole_commands(ipv4_list, ipv6_list, remove_ip=(del_ip, index_to_remove))
        output = execute_ssh_commands(commands)

        # Verify the removal
        commands = generate_blackhole_commands(ipv4_list, ipv6_list, list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        log += "Verification of removal...\n"
        if any(ip == del_ip for _, ip in ipv4_prefixes + ipv6_prefixes):
            log += f"Failed to remove IP prefix {del_ip}\n"
        else:
            log += f"IP prefix {del_ip} removed successfully\n"

        if del_ip in ipv4_routes + ipv6_routes:
            log += f"Failed to remove IP route {del_ip}\n"
        else:
            log += f"IP route {del_ip} removed successfully\n"
    elif clean_all:
        # List all IPs first
        commands = generate_blackhole_commands([], [], list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        # Remove all listed IPs
        commands = ["system"]
        ipv4_removed = []
        ipv6_removed = []
        if ipv4_prefixes:
            for index, ipv4 in ipv4_prefixes:
                commands.append(f"undo ip ip-prefix BLACKHOLE-OUT index {index}")
                commands.append(f"undo ip route-static {ipv4} 255.255.255.255 NULL0")
                ipv4_removed.append(ipv4)
        if ipv6_prefixes:
            for index, ipv6 in ipv6_prefixes:
                commands.append(f"undo ip ipv6-prefix BLACKHOLE-OUT index {index}")
                commands.append(f"undo ipv6 route-static {ipv6} 128 NULL0")
                ipv6_removed.append(ipv6)
        commands.append("commit")
        
        output = execute_ssh_commands(commands)

        # Verify the removal
        commands = generate_blackhole_commands([], [], list_only=True)
        output = execute_ssh_commands(commands)
        ipv4_prefixes, ipv6_prefixes, ipv4_routes, ipv6_routes = parse_blackhole_configuration(output)

        log += "Verification of removal of all IPs...\n"
        if ipv4_removed:
            log += "Removed IPv4 prefixes:\n" + "\n".join(ipv4_removed) + "\n"
        else:
            log += "No IPv4 prefixes found\n"

        if ipv4_removed:
            log += "Removed IPv4 routes:\n" + "\n".join(ipv4_removed) + "\n"
        else:
            log += "No IPv4 routes found\n"

        if ipv6_removed:
            log += "Removed IPv6 prefixes:\n" + "\n".join(ipv6_removed) + "\n"
        else:
            log += "No IPv6 prefixes found\n"

        if ipv6_removed:
            log += "Removed IPv6 routes:\n" + "\n".join(ipv6_removed) + "\n"
        else:
            log += "No IPv6 routes found\n"
    else:
        print(f"Invalid option: {option}")
        print_help()
        sys.exit(1)

    send_email(log)

if __name__ == "__main__":
    main()
