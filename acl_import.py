import re
import json
import requests
import os
import logging
import urllib3
import csv
import sys
import ipaddress
from dotenv import load_dotenv
from datetime import datetime
from prettytable import PrettyTable
from collections import defaultdict
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Disable HTTPS untrusted warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color definitions
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RED = Fore.RED
GREEN = Fore.GREEN
RESET = Style.RESET_ALL

def print_red(text):
    print(RED + text + RESET)

def print_green(text):
    print(GREEN + text + RESET)

def print_yellow(text):
    print(YELLOW + text + RESET)

def print_magenta(text):
    print(MAGENTA + text + RESET)

def print_disclaimer():
    print_yellow("\n\nDISCLAIMER:")
    print_yellow("###################################")
    print_yellow("This script is provided 'as is' without any guarantees or warranty.")
    print_yellow("The use of this script is at your own risk and you are fully responsible for any consequences resulting from its use.")
    print_yellow("Before running this script, please ensure you have a full understanding of its function.")
    print_yellow("By proceeding with this script, you are acknowledging that you have read and understood this disclaimer.")
    print_yellow("###################################")

def accept_disclaimer():
    accept = input(f"{MAGENTA}\nDo you accept the disclaimer and acknowledge the risks? (yes/no): {RESET}").strip().lower()
    if accept != 'yes':
        print_red("You did not accept the disclaimer. Exiting.")
        sys.exit(1)

# Load environment variables from .env file
load_dotenv()

# Configure logging
# Get the directory where the script is located
script_dir = os.path.dirname(os.path.abspath(__file__))
log_file_path = os.path.join(script_dir, 'acl_to_api.log')
logging.basicConfig(
    filename=log_file_path, 
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s\n%(message)s\n',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def login_to_psm():
    username = os.getenv('USERNAME')
    password = os.getenv('PASSWORD')
    apigwurl = os.getenv('APIGWURL')

    s = requests.Session()
    login_url = f"{apigwurl}/v1/login"
    login_headers = {'Content-Type': 'application/json'}
    login_data = {
        "username": username,
        "password": password,
        "tenant": "default"
    }
    response = s.post(login_url, headers=login_headers, json=login_data, verify=False)
    if response.status_code == 200:
        print_green("Successfully logged in to PSM")
        logging.info("Successfully logged in to PSM")
        return s
    else:
        print_red(f"Failed to log in to PSM. Status code: {response.status_code}")
        logging.error(f"Failed to log in to PSM. Status code: {response.status_code}")
        return None

def read_acl_file(filename):
    with open(filename, 'r') as file:
        return file.readlines()

def read_service_translation(filename):
    translations = {}
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split('=')
            if len(parts) == 2:
                key, value = parts
                translations[key.strip()] = value.strip()
    return translations

def read_translation_file(filename):
    translations = {}
    with open(filename, 'r') as file:
        for line in file:
            parts = line.strip().split('=')
            if len(parts) == 2:
                key, value = parts
                translations[key.strip()] = value.strip()
    return translations

def is_ipv6(ip_str):
    """Check if an IP string is IPv6"""
    if ip_str.lower() == 'any':
        return None
    try:
        # Remove subnet mask if present
        ip_part = ip_str.split('/')[0]
        ip_obj = ipaddress.ip_address(ip_part)
        return isinstance(ip_obj, ipaddress.IPv6Address)
    except ValueError:
        return False

def detect_acl_address_family(acl_entries):
    """Detect the address family of the ACL from the first non-'any' IP address"""
    for entry in acl_entries:
        # Check source first
        if entry['source'] != 'any':
            if is_ipv6(entry['source']) is True:
                return "IPv6"
            elif is_ipv6(entry['source']) is False:
                return "IPv4"
        
        # Then check destination
        if entry['destination'] != 'any':
            if is_ipv6(entry['destination']) is True:
                return "IPv6"
            elif is_ipv6(entry['destination']) is False:
                return "IPv4"
    
    # If all entries are 'any' to 'any', default to IPv4
    return "IPv4"

def validate_acl_consistency(acl_entries, address_family):
    """Validate that all ACL entries match the detected address family"""
    inconsistent_entries = []
    
    for entry in acl_entries:
        entry_inconsistent = False
        
        # Check source
        if entry['source'] != 'any':
            source_is_ipv6 = is_ipv6(entry['source'])
            if source_is_ipv6 is True and address_family == "IPv4":
                entry_inconsistent = True
            elif source_is_ipv6 is False and address_family == "IPv6":
                entry_inconsistent = True
        
        # Check destination
        if entry['destination'] != 'any':
            dest_is_ipv6 = is_ipv6(entry['destination'])
            if dest_is_ipv6 is True and address_family == "IPv4":
                entry_inconsistent = True
            elif dest_is_ipv6 is False and address_family == "IPv6":
                entry_inconsistent = True
        
        if entry_inconsistent:
            inconsistent_entries.append(entry)
    
    return inconsistent_entries

def validate_and_correct_ip_range(ip_range):
    # Skip validation for "any" keyword
    if ip_range.lower() == 'any':
        return ip_range, None
    
    # Check if it's a single IP address without subnet notation
    try:
        ip_obj = ipaddress.ip_address(ip_range)
        return ip_range, None
    except ValueError:
        pass  # Not a single IP address, continue with subnet validation
    
    try:
        # Split the IP and mask
        ip, mask = ip_range.split('/')
        mask = int(mask)
        
        # Create an IP network object (works for both IPv4 and IPv6)
        network = ipaddress.ip_network(ip_range, strict=False)
        
        # Get the correct network address
        correct_network = str(network.network_address)
        
        # If the original IP is not the network address, it needs correction
        if ip != correct_network:
            corrected_range = f"{correct_network}/{mask}"
            return corrected_range, f"{ip_range} corrected to {corrected_range}"
        
        return ip_range, None
    except ValueError:
        # If the IP range is invalid, return it as is with an error message
        return ip_range, f"Invalid IP range: {ip_range}"

def parse_ace(line, service_translations, protocol_translations):
    pattern = r'(\d+)\s+(permit|deny)\s+(\w+)\s+(\S+)(?:\s+eq\s+(\S+))?\s+(\S+)(?:\s+(.+))?'
    match = re.match(pattern, line.strip())
    if match:
        sqn = match.group(1)
        action = match.group(2)
        protocol = match.group(3)
        source = match.group(4)
        source_port = match.group(5)
        destination = match.group(6)
        remaining = match.group(7) or ''

        # Handle ICMPv6
        if protocol.lower() == 'icmpv6':
            protocol = 'icmpv6'
        elif protocol.lower() in protocol_translations:
            protocol = protocol_translations[protocol.lower()]
        elif protocol.lower() == 'ip':
            protocol = 'any'

        # Validate and correct IP ranges
        source, source_correction = validate_and_correct_ip_range(source)
        destination, dest_correction = validate_and_correct_ip_range(destination)

        port = ''
        if remaining:
            parts = remaining.split()
            if parts[0].lower() == 'eq' and len(parts) > 1:
                port_name = parts[1]
                port = service_translations.get(port_name, port_name)
            elif parts[0].lower() == 'range' and len(parts) > 2:
                start_port = service_translations.get(parts[1], parts[1])
                end_port = service_translations.get(parts[2], parts[2])
                port = f"{start_port}-{end_port}"
            elif parts[0].lower() == 'gt' and len(parts) > 1:
                start_port = service_translations.get(parts[1], parts[1])
                port = f"{start_port}-65535"
            elif parts[0].lower() == 'lt' and len(parts) > 1:
                end_port = service_translations.get(parts[1], parts[1])
                port = f"1-{end_port}"

        return {
            'sqn': sqn,
            'action': action,
            'protocol': protocol,
            'source': source,
            'destination': destination,
            'port': port,
            'source_port': source_port,  # Include source_port in the returned dictionary
            'source_correction': source_correction,
            'dest_correction': dest_correction,
            'original_line': line.strip()  # Store original line for reporting
        }
    logging.debug(f"No match found for line: {line.strip()}")
    return None

def create_policy_payload(acl_entries, address_family="IPv4"):
    # Get the display name and rule name prefix from environment variables
    display_name = os.getenv('DISPLAY_NAME', 'ACL-Import')
    rule_name_prefix = os.getenv('RULE_NAME_PREFIX', 'ACE-rule')
    
    # Add timestamp to display name to ensure uniqueness
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    display_name = f"{display_name}-{timestamp}"

    rules = []
    for i, ace in enumerate(acl_entries, 1):
        rule = {
            "action": ace['action'],
            "name": f"{rule_name_prefix}-{i}",
            "proto-ports": [
                {
                    "protocol": ace['protocol']
                }
            ]
        }
        
        # Handle source IP addresses
        if ace['source'] == 'any':
            rule["from-ip-addresses"] = ["any"]
        else:
            rule["from-ip-addresses"] = [ace['source']] if isinstance(ace['source'], str) else ace['source']
        
        # Handle destination IP addresses
        if ace['destination'] == 'any':
            rule["to-ip-addresses"] = ["any"]
        else:
            rule["to-ip-addresses"] = [ace['destination']] if isinstance(ace['destination'], str) else ace['destination']
        
        # Handle ports for TCP and UDP
        if ace['protocol'].lower() in ['tcp', 'udp']:
            if ace['port']:
                rule["proto-ports"][0]["ports"] = ace['port']
            else:
                rule["proto-ports"][0]["ports"] = "0-65535"
        
        rules.append(rule)

    return {
        "kind": "NetworkSecurityPolicy",
        "api-version": "v1",
        "meta": {
            "name": None,  # Keep this empty to allow system-generated name
            "tenant": "default",
            "namespace": "default",
            "display-name": display_name
        },
        "spec": {
            "attach-tenant": True,
            "rules": rules,
            "policy-distribution-targets": [
                "default"
            ],
            "address-family": address_family
        }
    }

def display_sqn_merge_table(optimized_rules):
    table = PrettyTable()
    table.field_names = ["Rule Name", "Original SQNs"]
    
    for i, rule in enumerate(optimized_rules, 1):
        table.add_row([f"ACE-rule-{i}", ', '.join(rule['sqns'])])
    
    #print("\nSQN Merge Table:")
    #print(table)

def save_sqn_merge_csv(optimized_rules, filename='sqn_merge_table.csv'):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Rule Name', 'Original SQNs'])
        for i, rule in enumerate(optimized_rules, 1):
            writer.writerow([f"ACE-rule-{i}", ', '.join(rule['sqns'])])
    print_green(f"\nSQN merge table saved to {filename}")
    
def export_rules_to_csv(rules, filename='rules_export.csv'):
    with open(filename, 'w', newline='') as csvfile:
        fieldnames = ['action', 'name', 'description', 'from-ip-addresses', 'to-ip-addresses', 
                      'from-workload-groups', 'to-workload-groups', 'protocol', 'ports', 'apps']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for rule in rules:
            csv_rule = {
                'action': rule['action'],
                'name': rule['name'],
                'description': '',
                'from-ip-addresses': ','.join(rule['from-ip-addresses']),
                'to-ip-addresses': ','.join(rule['to-ip-addresses']),
                'from-workload-groups': '',
                'to-workload-groups': '',
                'protocol': rule['proto-ports'][0]['protocol'],
                'ports': rule['proto-ports'][0].get('ports', ''),
                'apps': ''
            }
            writer.writerow(csv_rule)
    
    print_green(f"\nRules exported to CSV file: {filename}")

def send_api_request(session, method, url, payload):
    response = session.request(method, url, json=payload, verify=False)
    if response.status_code not in (200, 201):
        logging.error(f"API request failed. Status code: {response.status_code}")
        logging.error(f"Request URL: {url}")
        logging.error(f"Request method: {method}")
        logging.error(f"Request payload:\n{json.dumps(payload, indent=2)}")
        logging.error(f"Response content:\n{response.text}")
        return None
    try:
        return response.json()
    except json.JSONDecodeError:
        logging.error("Failed to decode JSON response")
        logging.error(f"Response content:\n{response.text}")
        return None

def display_acl_table(acl_entries):
    table = PrettyTable()
    table.field_names = ["ACE ID", "Action", "Protocol", "Source", "Destination", "Port"]
    for entry in acl_entries:
        table.add_row([
            entry['sqn'],
            entry['action'],
            entry['protocol'],
            entry['source'],
            entry['destination'],
            entry['port']
        ])
    print(table)

def check_duplicates(acl_entries):
    seen = {}
    duplicates = []
    for entry in acl_entries:
        key = (entry['action'], entry['protocol'], entry['source'], entry['destination'], entry['port'])
        if key in seen:
            duplicates.append((seen[key], entry['sqn']))
        else:
            seen[key] = entry['sqn']
    return duplicates

def optimize_rules(acl_entries):
    optimized = []
    catch_all_rules = []
    
    for entry in acl_entries:
        if entry['source'] == 'any' and entry['destination'] == 'any':
            catch_all_rules.append({**entry, 'sqns': [entry['sqn']]})
        else:
            optimized.append(entry)
    
    # Group rules by action, protocol, and port
    grouped_rules = defaultdict(list)
    for rule in optimized:
        key = (rule['action'], rule['protocol'], rule['port'])
        grouped_rules[key].append(rule)
    
    final_rules = []
    for key, entries in grouped_rules.items():
        if len(entries) == 1:
            final_rules.append({**entries[0], 'sqns': [entries[0]['sqn']]})
        else:
            # Group by source
            source_groups = defaultdict(list)
            for entry in entries:
                source_groups[entry['source']].append(entry)
            
            for source, group in source_groups.items():
                if len(group) > 1:
                    destinations = set(entry['destination'] for entry in group if entry['destination'] != 'any')
                    if destinations:
                        final_rules.append({
                            'action': key[0],
                            'protocol': key[1],
                            'port': key[2],
                            'source': source,
                            'destination': list(destinations) if len(destinations) > 1 else list(destinations)[0],
                            'sqns': [entry['sqn'] for entry in group]
                        })
                    else:
                        for entry in group:
                            final_rules.append({**entry, 'sqns': [entry['sqn']]})
                else:
                    final_rules.append({**group[0], 'sqns': [group[0]['sqn']]})
    
    # Append catch-all rules at the end, maintaining their original order
    final_rules.extend(catch_all_rules)
    
    return final_rules

def print_rules_to_file(rules, filename='optimized_rules.txt'):
    with open(filename, 'w') as f:
        for i, rule in enumerate(rules, 1):
            f.write(f"ACE-rule-{i}:\n")
            f.write(f"Action: {rule['action']}, Protocol: {rule['protocol']}, Port: {rule['port']}\n")
            f.write(f"Source: {rule['source'] if isinstance(rule['source'], str) else ', '.join(rule['source'])}\n")
            f.write(f"Destination: {rule['destination'] if isinstance(rule['destination'], str) else ', '.join(rule['destination'])}\n")
            f.write(f"Original SQNs: {', '.join(rule['sqns'])}\n\n")
    print_green(f"\nOptimized rules have been written to {filename}")

def print_processing_summary(stats):
    """Print a comprehensive summary of ACL processing"""
    print_magenta("\n" + "="*80)
    print_magenta("ACL PROCESSING SUMMARY")
    print_magenta("="*80 + "\n")
    
    # Overall statistics
    table = PrettyTable()
    table.field_names = ["Metric", "Count"]
    table.align["Metric"] = "l"
    table.align["Count"] = "r"
    
    table.add_row(["Total ACL entries processed", stats['total_entries']])
    table.add_row(["Valid ACL entries parsed", stats['valid_entries']])
    table.add_row(["Final firewall rules created", stats['final_rules']])
    table.add_row(["Compression ratio", f"{stats['compression_ratio']:.1f}:1"])
    
    print(table)
    
    # Address family detection
    print_yellow(f"\nDetected Address Family: {stats['address_family']}")
    
    # Inconsistent entries
    if stats.get('inconsistent_entries', 0) > 0:
        print_red(f"\nWARNING: {stats['inconsistent_entries']} entries inconsistent with {stats['address_family']} ACL!")
        print_red("         These entries were dropped as they don't match the ACL address family.")
    
    # Dropped rules summary
    if stats['dropped_rules']:
        print_red(f"\nDropped Rules Summary ({len(stats['dropped_rules'])} total):")
        
        drop_table = PrettyTable()
        drop_table.field_names = ["Reason", "Count", "ACL SQNs"]
        drop_table.align["Reason"] = "l"
        drop_table.align["Count"] = "r"
        drop_table.align["ACL SQNs"] = "l"
        
        # Group dropped rules by reason
        drop_reasons = defaultdict(list)
        for rule in stats['dropped_rules']:
            drop_reasons[rule['reason']].append(rule['sqn'])
        
        for reason, sqns in drop_reasons.items():
            sqn_list = ', '.join(sqns[:5])  # Show first 5 SQNs
            if len(sqns) > 5:
                sqn_list += f" ... ({len(sqns)-5} more)"
            drop_table.add_row([reason, len(sqns), sqn_list])
        
        print(drop_table)
    
    # Corrections made
    if stats['ip_corrections']:
        print_yellow(f"\nIP Range Corrections ({len(stats['ip_corrections'])} total):")
        for i, correction in enumerate(stats['ip_corrections'][:5]):
            print_yellow(f"  {correction}")
        if len(stats['ip_corrections']) > 5:
            print_yellow(f"  ... and {len(stats['ip_corrections'])-5} more corrections")
    
    # Optimization summary
    if stats['merge_count'] > 0:
        print_green(f"\nOptimization Results:")
        print_green(f"  - Rules merged: {stats['merge_count']}")
        print_green(f"  - Space saved: {stats['valid_entries'] - stats['final_rules']} rules")
    
    # Save detailed report
    report_file = 'acl_processing_report.txt'
    with open(report_file, 'w') as f:
        f.write("ACL PROCESSING DETAILED REPORT\n")
        f.write("="*80 + "\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("STATISTICS:\n")
        f.write(f"  Total ACL entries: {stats['total_entries']}\n")
        f.write(f"  Valid entries: {stats['valid_entries']}\n")
        f.write(f"  Final rules: {stats['final_rules']}\n")
        f.write(f"  Compression ratio: {stats['compression_ratio']:.1f}:1\n")
        f.write(f"  Address family: {stats['address_family']}\n\n")
        
        if stats['dropped_rules']:
            f.write("DROPPED RULES:\n")
            for rule in stats['dropped_rules']:
                f.write(f"  SQN {rule['sqn']}: {rule['reason']}\n")
                if 'line' in rule:
                    f.write(f"    Original: {rule['line']}\n")
            f.write("\n")
        
        if stats['ip_corrections']:
            f.write("IP CORRECTIONS:\n")
            for correction in stats['ip_corrections']:
                f.write(f"  {correction}\n")
    
    print_green(f"\nDetailed report saved to: {report_file}")

def main():
    print("Entering main function")
    print_disclaimer()
    accept_disclaimer()

    acl_file = 'acl.txt'
    service_translation_file = 'service_translation.txt'
    protocol_translation_file = 'protocol_translation.txt'
    
    logging.info("Script execution started")
    
    session = login_to_psm()
    if not session:
        print_red("Failed to login to PSM. Exiting script.")
        logging.error("Failed to login to PSM. Exiting script.")
        return

    # Try to read translation files with error handling
    try:
        service_translations = read_translation_file(service_translation_file)
    except FileNotFoundError:
        print_yellow(f"\nWarning: Service translation file '{service_translation_file}' not found.")
        print_yellow("Continuing without service name translations...")
        service_translations = {}
    
    try:
        protocol_translations = read_translation_file(protocol_translation_file)
    except FileNotFoundError:
        print_yellow(f"\nWarning: Protocol translation file '{protocol_translation_file}' not found.")
        print_yellow("Continuing without protocol translations...")
        protocol_translations = {}
    
    # Try to read ACL file with error handling
    acl_lines = []
    while True:
        try:
            acl_lines = read_acl_file(acl_file)
            break
        except FileNotFoundError:
            print_yellow(f"\nFile '{acl_file}' not found.")
            
            # Show available .txt files in current directory
            import glob
            txt_files = glob.glob("*.txt")
            if txt_files:
                print_yellow("\nAvailable .txt files in current directory:")
                for f in sorted(txt_files):
                    print_yellow(f"  - {f}")
            
            acl_file = input("\nPlease enter the ACL filename (or 'exit' to quit): ").strip()
            if acl_file.lower() == 'exit':
                print_yellow("Exiting script.")
                return
            if not acl_file:
                acl_file = 'acl.txt'
    
    # Initialize tracking
    acl_entries = []
    stats = {
        'total_entries': len(acl_lines),
        'valid_entries': 0,
        'final_rules': 0,
        'compression_ratio': 1.0,
        'dropped_rules': [],
        'ip_corrections': [],
        'merge_count': 0,
        'address_family': 'IPv4',
        'inconsistent_entries': 0
    }
    
    established_rules = []
    source_port_rules = []

    for line in acl_lines:
        ace = parse_ace(line, service_translations, protocol_translations)
        if ace:
            # Track established rules
            if 'established' in line:
                established_rules.append(line.strip())
                stats['dropped_rules'].append({
                    'sqn': ace['sqn'],
                    'reason': 'Established keyword not supported',
                    'line': line.strip()
                })
                continue
            
            # Track source port rules
            if ace['source_port']:
                logging.debug(f"Source port rule detected: {line.strip()}")
                ace['source_port'] = None
                source_port_rules.append(line.strip())
                stats['dropped_rules'].append({
                    'sqn': ace['sqn'],
                    'reason': 'Source port filtering not supported by PSM',
                    'line': line.strip()
                })
            
            acl_entries.append(ace)
            stats['valid_entries'] += 1
            
            # Track IP corrections
            if ace['source_correction']:
                stats['ip_corrections'].append(ace['source_correction'])
            if ace['dest_correction']:
                stats['ip_corrections'].append(ace['dest_correction'])

    # Detect address family from the ACL
    stats['address_family'] = detect_acl_address_family(acl_entries)
    
    # Validate consistency and remove inconsistent entries
    inconsistent_entries = validate_acl_consistency(acl_entries, stats['address_family'])
    if inconsistent_entries:
        stats['inconsistent_entries'] = len(inconsistent_entries)
        for entry in inconsistent_entries:
            stats['dropped_rules'].append({
                'sqn': entry['sqn'],
                'reason': f'Address family mismatch in {stats["address_family"]} ACL',
                'line': entry.get('original_line', 'N/A')
            })
        # Remove inconsistent entries from acl_entries
        acl_entries = [e for e in acl_entries if e not in inconsistent_entries]
        stats['valid_entries'] = len(acl_entries)
    
    print_green(f"Parsed {len(acl_entries)} ACL entries")
    print_green(f"Detected address family: {stats['address_family']}")
    logging.info(f"Parsed {len(acl_entries)} ACL entries")
    logging.info(f"Detected address family: {stats['address_family']}")

    if established_rules:
        print_yellow("\nWarning: The following rules with 'established' keyword were removed:")
        for rule in established_rules:
            print_yellow(f"  {rule}")
        logging.warning(f"Rules with 'established' keyword removed: {established_rules}")

    if source_port_rules:
        print_yellow("\nWarning: The following rules with source ports were adapted (source port removed):")
        for rule in source_port_rules:
            print_yellow(f"  {rule}")
        logging.warning(f"Rules with source ports adapted: {source_port_rules}")

    if stats['ip_corrections']:
        print_yellow("\nWarning: The following IP ranges were corrected:")
        for correction in stats['ip_corrections'][:5]:  # Show first 5
            print_yellow(f"  {correction}")
        if len(stats['ip_corrections']) > 5:
            print_yellow(f"  ... and {len(stats['ip_corrections'])-5} more corrections")
        logging.warning(f"IP ranges corrected: {stats['ip_corrections']}")

    # Ask user if they want to optimize rules
    optimize = input("\nDo you want to optimize the rules? (yes/no): ").lower() == 'yes'
    
    if optimize:
        optimized_rules = optimize_rules(acl_entries)
        stats['final_rules'] = len(optimized_rules)
        stats['merge_count'] = stats['valid_entries'] - stats['final_rules']
        print_green("\nRules have been optimized.")
    else:
        optimized_rules = [{'action': ace['action'], 'protocol': ace['protocol'], 'port': ace['port'],
                            'source': ace['source'], 'destination': ace['destination'], 'sqns': [ace['sqn']]}
                           for ace in acl_entries]
        stats['final_rules'] = len(optimized_rules)
        print_green("\nRules have not been optimized.")

    # Calculate compression ratio
    if stats['final_rules'] > 0:
        stats['compression_ratio'] = stats['valid_entries'] / stats['final_rules']

    # Print processing summary
    print_processing_summary(stats)

    # Print rules to file
    print_rules_to_file(optimized_rules)

    # Display SQN merge table
    display_sqn_merge_table(optimized_rules)

    # Save SQN merge CSV
    save_sqn_merge_csv(optimized_rules)

    # Prompt user to continue
    user_input = input("\nDo you want to proceed with creating the policy? (yes/no): ").lower()
    if user_input != 'yes':
        print_yellow("Operation cancelled.")
        logging.info("Operation cancelled by user after displaying ACL entries")
        return

    # Create policy
    apigwurl = os.getenv('APIGWURL')
    policy_url = f"{apigwurl}/configs/security/v1/tenant/default/networksecuritypolicies"
    policy_payload = create_policy_payload(optimized_rules, stats['address_family'])

    # Show the display name that will be used
    print_green(f"\nPolicy will be created with display name: {policy_payload['meta']['display-name']}")
    
    # Export rules to CSV
    export_rules_to_csv(policy_payload['spec']['rules'])

    confirm = input("\nDo you want to send this policy to PSM? (yes/no): ").lower()
    if confirm != 'yes':
        print_yellow("Operation cancelled.")
        logging.info("Operation cancelled by user before sending policy to PSM")
        return

    print_green("Sending policy to PSM")
    logging.info("Sending policy to PSM")
    policy_response = send_api_request(session, 'POST', policy_url, policy_payload)
    
    if policy_response is None:
        print_red("Failed to create policy. Check the log for details.")
        logging.error("Failed to create policy")
        return

    print_green("\nPolicy created successfully.")
    logging.info("Policy created successfully")
    logging.info(f"Policy response:\n{json.dumps(policy_response, indent=2)}")

    print_green("Script execution completed")
    logging.info("Script execution completed")


if __name__ == "__main__":
    # Set up debug logging
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    main()