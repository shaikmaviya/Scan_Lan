from transformers import pipeline
from main import scan_ipaddresses, scan_vulnerabilities, scan_ports, ping_ip
import re

# Initialize NLP model
nlp = pipeline("text-classification")

def banner():
    banner="""

███████╗ ██████╗ █████╗ ███╗   ██╗    ██╗      █████╗ ███╗   ██╗
██╔════╝██╔════╝██╔══██╗████╗  ██║    ██║     ██╔══██╗████╗  ██║
███████╗██║     ███████║██╔██╗ ██║    ██║     ███████║██╔██╗ ██║
╚════██║██║     ██╔══██║██║╚██╗██║    ██║     ██╔══██║██║╚██╗██║
███████║╚██████╗██║  ██║██║ ╚████║    ███████╗██║  ██║██║ ╚████║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝    
    """
    print(banner)

def process_prompt(prompt):
    result = nlp(prompt)
    return result

def extract_ip_address(prompt):
    # Regex to match IP addresses
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, prompt)
    if match:
        return match.group(0)
    return None

def parse_prompt(prompt):
    if 'ipaddress' in prompt or 'ipaddresses' in prompt:
        return 'scan_ipaddresses'
    elif 'vulnerabilities' in prompt or 'vulnerabilite' in prompt:
        return 'scan_vulnerabilities'
    elif 'ping' in prompt or 'pingscan' in prompt:
        return 'ping_ip'
    elif 'ports' in prompt or 'port' in prompt:
        return 'scan_ports'
    
    return 'unknown_command'

def execute_command(command, ip_address):
    if command == 'scan_ipaddresses':
        try:
            result = scan_ipaddresses(ip_address)
            print(result)
        except Exception as e:
            print(f"Error scanning IP address: {e}")

    elif command == 'scan_vulnerabilities':
        try:
            result = scan_vulnerabilities(ip_address)
            print("Anomaly report generated successfully.")
        except Exception as e:
            print(f"Error generating anomaly report: {e}")

    elif command == 'ping_ip':
        try:
            result = ping_ip(ip_address)
            print(result)
        except Exception as e:
            print(f"Error pinging IP address: {e}")

    elif command == 'scan_ports':
        try:
            result = scan_ports(ip_address)
            print(result)
        except Exception as e:
            print(f"Error scanning ports: {e}")

    else:
        print("Unknown command")

if __name__ == "__main__":
    while True:
        banner()
        print("""You can scan the local area network (LAN) using this powerful tool, SCAN LAN, 
created by Shaik Maviya.
""")
        user_input = input("Enter your prompt: ")
        command = parse_prompt(user_input)
        ip_address = extract_ip_address(user_input)
        
        if ip_address:
            execute_command(command, ip_address)
        else:
            print("No valid IP address found in the input.")
