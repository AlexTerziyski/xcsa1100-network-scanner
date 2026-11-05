#!/usr/bin/env python3
# ============================================================================
# Student: Alex Terziyski
# Date: November 5th, 2026
# Course: XCSA-1100-MC1 - Network Programming for Security Analysts
# Instructor: Hamid Talebi
# Final Project: IP Port Scanner, OS Detection, and Geolocation Tool
# File: network_scanner.py
#
# Description:
# A Python security tool that takes an IP address or hostname from the user,
# resolves the target, scans common security ports using TCP sockets,
# detects the remote operating system by analyzing ICMP ping TTL values with
# regular expressions, looks up IP geolocation data through a REST API, and
# saves a timestamped scan report to a text file.
# ============================================================================

# Import the socket module to create and manage TCP/IP network connections
import socket
# Import subprocess to run operating system commands like ping
import subprocess
# Import sys to handle command-line arguments and system exit calls
import sys
# Import os to interact with the operating system environment
import os
# Import re to use regular expressions for text pattern matching
import re
# Import json to parse JSON data received from the geolocation API
import json
# Import urllib.request to send HTTP GET requests to the web API
import urllib.request
# Import urllib.error to catch any network errors when calling the API
import urllib.error
# Import datetime to get current timestamps for the scan and report
from datetime import datetime
# Import platform to determine if the computer runs Windows, Linux, or macOS
import platform


# Dictionary mapping common port numbers to their standard network service names
COMMON_PORTS = {
    21: "FTP (File Transfer Protocol)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Unencrypted Remote Login)",
    25: "SMTP (Simple Mail Transfer Protocol)",
    53: "DNS (Domain Name System)",
    80: "HTTP (Web Traffic)",
    110: "POP3 (Post Office Protocol)",
    135: "RPC (Remote Procedure Call)",
    139: "NetBIOS (NetBIOS Session Service)",
    143: "IMAP (Internet Message Access Protocol)",
    443: "HTTPS (Secure Web Traffic)",
    445: "SMB (Server Message Block / File Sharing)",
    993: "IMAPS (Secure IMAP)",
    995: "POP3S (Secure POP3)",
    1433: "MSSQL (Microsoft SQL Server)",
    1521: "Oracle (Oracle Database)",
    3306: "MySQL (MySQL Database)",
    3389: "RDP (Remote Desktop Protocol)",
    5432: "PostgreSQL (PostgreSQL Database)",
    8080: "HTTP-Proxy (Alternative Web Server)",
    8443: "HTTPS-Alt (Alternative Secure Web Server)"
}


# Function to resolve the target hostname or IP into a valid IPv4 address
def resolve_target(target):
    # Strip any leading and trailing whitespace from the user input
    clean_target = target.strip()
    
    # If the user entered an empty string, print an error and return None
    if not clean_target:
        # Inform the user that the input cannot be empty
        print("[-] Error: Target host cannot be blank.")
        # Return None to indicate failure
        return None
    
    # Remove http:// prefix if the user typed or pasted a URL
    if clean_target.startswith("http://"):
        # Slice off the first 7 characters
        clean_target = clean_target[7:]
    # Remove https:// prefix if the user pasted a secure URL
    elif clean_target.startswith("https://"):
        # Slice off the first 8 characters
        clean_target = clean_target[8:]
    
    # Remove any trailing path if the user included a slash like example.com/page
    if "/" in clean_target:
        # Keep only the part before the first forward slash
        clean_target = clean_target.split("/")[0]
        
    # Remove any port number if the user entered host:port format
    if ":" in clean_target and clean_target.count(":") == 1:
        # Keep only the hostname portion before the colon
        clean_target = clean_target.split(":")[0]

    # Display which target is currently being resolved
    print(f"[*] Resolving target: {clean_target}")

    # Use a try-except block to handle DNS resolution errors safely
    try:
        # socket.gethostbyname translates a domain name to its IPv4 address
        resolved_ip = socket.gethostbyname(clean_target)
        # Print the resolved IP address to confirm success
        print(f"[+] Target resolved: {clean_target} -> {resolved_ip}")
        # Return the resolved IPv4 address as a string
        return resolved_ip
    # Catch socket.gaierror which happens when a hostname cannot be resolved
    except socket.gaierror as error:
        # Print a clear error message explaining DNS lookup failed
        print(f"[-] DNS Resolution Error: Could not resolve '{clean_target}' ({error})")
        # Return None so the caller knows the target was invalid
        return None
    # Catch any generic socket error that might happen
    except socket.error as error:
        # Print the specific socket error details
        print(f"[-] Socket error during resolution: {error}")
        # Return None to indicate resolution failure
        return None


# Function to detect the remote operating system using ICMP ping and TTL regex
def detect_os(ip_address):
    # Print a status message indicating OS fingerprinting has started
    print("\n[*] Running OS fingerprinting via ICMP ping...")
    
    # Check the host operating system name in lowercase (e.g., 'windows' or 'linux')
    os_name = platform.system().lower()
    
    # If running on Windows, build ping command with -n flag for packet count
    if "windows" in os_name:
        # -n 1 sends one echo request, -w 2000 sets a 2-second timeout in milliseconds
        cmd = ["ping", "-n", "1", "-w", "2000", ip_address]
    # If running on macOS (Darwin), the -W flag is in milliseconds (2000 ms = 2 seconds)
    elif "darwin" in os_name:
        # -c 1 sends one packet, -W 2000 sets a 2000ms (2s) timeout on macOS
        cmd = ["ping", "-c", "1", "-W", "2000", ip_address]
    # Otherwise, assume Linux where the -W flag is in seconds
    else:
        # -c 1 sends one packet, -W 2 sets a 2-second timeout on Linux
        cmd = ["ping", "-c", "1", "-W", "2", ip_address]

    # Initialize a dictionary to store our detection findings
    os_info = {
        "ttl": None,
        "initial_ttl": None,
        "estimated_hops": 0,
        "os_name": "Unknown (Ping blocked or host timed out)"
    }

    # Use try-except to catch execution errors or timeouts when running ping
    try:
        # subprocess.run executes the ping command and captures the output
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        # Save the standard output text from the ping command
        output = result.stdout

        # Use regular expression to find the TTL value in the ping output
        # re.IGNORECASE matches both lowercase 'ttl=' and uppercase 'TTL='
        # (\d+) captures one or more numbers directly following the ttl label
        match = re.search(r"ttl[=\s](\d+)", output, re.IGNORECASE)

        # Check if the regex found a match in the command output
        if match:
            # Convert the first captured group to an integer
            ttl = int(match.group(1))
            # Store the extracted TTL in our dictionary
            os_info["ttl"] = ttl

            # Standard TTL heuristic: Linux and macOS usually start with a TTL of 64
            if ttl <= 64:
                # Set initial TTL baseline to 64
                os_info["initial_ttl"] = 64
                # Calculate network hops: Initial TTL minus received TTL
                os_info["estimated_hops"] = 64 - ttl
                # Set the identified operating system family
                os_info["os_name"] = "Linux / Unix / macOS / Android"

            # Windows systems usually start with a default TTL of 128
            elif ttl <= 128:
                # Set initial TTL baseline to 128
                os_info["initial_ttl"] = 128
                # Calculate hops traversed: 128 minus received TTL
                os_info["estimated_hops"] = 128 - ttl
                # Set the identified operating system family
                os_info["os_name"] = "Microsoft Windows"

            # Cisco routers and network appliances usually start with a TTL of 255
            elif ttl <= 255:
                # Set initial TTL baseline to 255
                os_info["initial_ttl"] = 255
                # Calculate hops traversed: 255 minus received TTL
                os_info["estimated_hops"] = 255 - ttl
                # Set the identified operating system family
                os_info["os_name"] = "Cisco Router / Solaris / Network Device"

            # Print out the captured values clearly for the analyst
            print(f"[+] Received ICMP Echo Reply: TTL = {ttl}")
            # Print the estimated starting TTL
            print(f"    - Baseline TTL: {os_info['initial_ttl']}")
            # Print the number of hops the packet traversed
            print(f"    - Estimated Router Hops: {os_info['estimated_hops']}")
            # Print the identified operating system
            print(f"    - Detected OS: {os_info['os_name']}")
        # If no TTL was found in the output, the target might be filtering ping
        else:
            # Inform the user that ping did not return a TTL
            print("[-] Warning: No TTL found in ping output (ICMP may be blocked by a firewall).")

    # Handle subprocess timeout if ping takes longer than 5 seconds
    except subprocess.TimeoutExpired:
        # Print a notice that the ping timed out
        print("[-] Ping timed out after 5 seconds.")
    # Handle the rare case where ping executable is missing
    except FileNotFoundError:
        # Print that the ping command was not found on this machine
        print("[-] Error: 'ping' command was not found on this system.")
    # Catch any other unexpected subprocess errors
    except Exception as e:
        # Print the error details
        print(f"[-] Subprocess error during OS detection: {e}")

    # Return the dictionary with OS detection findings
    return os_info


# Function to scan TCP ports using Python socket library
def scan_ports(ip_address, ports_dict=COMMON_PORTS):
    # Print the start of the port scanning phase
    print(f"\n[*] Scanning {len(ports_dict)} common security ports on {ip_address}...")
    # Print the column headers for the results table
    print(f"{'PORT':<8} {'STATUS':<10} {'SERVICE'}")
    # Print a clean horizontal divider line
    print("-" * 55)

    # Create an empty list to store all open ports found during the scan
    open_ports = []

    # Loop through each port and its service description in the dictionary
    for port, service in sorted(ports_dict.items()):
        # Initialize the socket variable to None
        sock = None
        # Use try-except-finally to manage the socket lifecycle cleanly
        try:
            # Create a TCP IPv4 socket: AF_INET = IPv4, SOCK_STREAM = TCP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set a 0.8 second timeout so closed ports do not hang the program
            sock.settimeout(0.8)
            # connect_ex tries the 3-way handshake and returns 0 if successful
            result = sock.connect_ex((ip_address, port))

            # If result is 0, the port is open and accepting connections
            if result == 0:
                # Print the open port and its service in the formatted table
                print(f"{port:<8} {'OPEN':<10} {service}")
                # Append a dictionary with port details to our open_ports list
                open_ports.append({
                    "port": port,
                    "service": service
                })
        # Catch any socket error that may occur during the connection attempt
        except socket.error as err:
            # Print a brief warning for the failed port check
            print(f"[-] Socket error on port {port}: {err}")
        # Finally block runs every time to guarantee socket resources are released
        finally:
            # Check if the socket object was created
            if sock:
                # Close the socket connection
                sock.close()

    # Print a closing line for the port table
    print("-" * 55)
    # Print the total count of open ports detected
    print(f"[+] Scan finished: Found {len(open_ports)} open port(s).")
    # Return the list of open ports
    return open_ports


# Function to query external geolocation and network metadata via REST API
def get_ip_geolocation(ip_address):
    # Print that the geolocation API lookup is beginning
    print("\n[*] Querying Geolocation & Threat Intelligence API...")

    # Check if the IP is a private RFC 1918 or local loopback address
    is_private = (
        ip_address.startswith("127.") or
        ip_address.startswith("10.") or
        ip_address.startswith("192.168.") or
        ip_address == "localhost" or
        (ip_address.startswith("172.") and 16 <= int(ip_address.split(".")[1]) <= 31)
    )

    # If the target is a private IP, public APIs cannot look it up
    if is_private:
        # Print that this is a private internal address
        print("[*] Target is a private or loopback IP address (RFC 1918).")
        # Return a dictionary indicating local network status
        return {
            "country": "Local Network (Private Subnet)",
            "city": "Private Gateway",
            "isp": "Local Loopback / Intranet",
            "as": "Private (N/A)"
        }

    # Construct the API endpoint URL for ip-api.com asking for specific fields
    url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,isp,as"

    # Default metadata dictionary in case the API call fails
    geo_data = {
        "country": "Unknown",
        "city": "Unknown",
        "isp": "Unknown",
        "as": "Unknown"
    }

    # Use try-except to handle HTTP errors or connectivity issues
    try:
        # Create an HTTP request object with a custom User-Agent header
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "XCSA1100-Student-Scanner/1.0"}
        )
        # Open the URL with a 5-second timeout
        with urllib.request.urlopen(req, timeout=5) as response:
            # Read the raw response bytes from the server
            data_bytes = response.read()
            # Decode the bytes into a UTF-8 string and parse into a dictionary
            parsed = json.loads(data_bytes.decode("utf-8"))

            # Check if the API returned a successful status
            if parsed.get("status") == "success":
                # Extract the country name
                geo_data["country"] = parsed.get("country", "Unknown")
                # Extract the city name
                geo_data["city"] = parsed.get("city", "Unknown")
                # Extract the Internet Service Provider name
                geo_data["isp"] = parsed.get("isp", "Unknown")
                # Extract the Autonomous System (AS) number and name
                geo_data["as"] = parsed.get("as", "Unknown")

                # Print the retrieved geolocation details
                print(f"[+] Location: {geo_data['city']}, {geo_data['country']}")
                # Print the ISP provider
                print(f"[+] ISP: {geo_data['isp']}")
                # Print the Autonomous System
                print(f"[+] Autonomous System: {geo_data['as']}")
            # Handle API-level error message
            else:
                # Print the message returned by the API
                print(f"[-] Geolocation API notice: {parsed.get('message', 'Lookup failed')}")

    # Catch HTTP status errors (like 404 or 500)
    except urllib.error.HTTPError as http_err:
        # Print the HTTP error code and reason
        print(f"[-] HTTP Error querying API: {http_err.code} ({http_err.reason})")
    # Catch URL and connection errors (like DNS failure or no internet)
    except urllib.error.URLError as url_err:
        # Print the connection error reason
        print(f"[-] Network Error querying API: {url_err.reason}")
    # Catch JSON parsing errors if response is not valid JSON
    except json.JSONDecodeError:
        # Print that the server response could not be parsed
        print("[-] Error: Could not decode JSON response from API.")
    # Catch any other unexpected error
    except Exception as e:
        # Print the generic error message
        print(f"[-] Unexpected error in API lookup: {e}")

    # Return the populated geolocation dictionary
    return geo_data


# Function to save all scan findings to a timestamped text file
def save_report(target_host, target_ip, os_info, open_ports, geo_data, start_time):
    # Print a status message indicating the report is being saved
    print("\n[*] Saving scan report to file...")

    # Record the time the scan finished
    end_time = datetime.now()
    # Calculate the elapsed scan time in seconds
    elapsed_seconds = (end_time - start_time).total_seconds()

    # Replace dots in IP address with underscores to make a safe filename
    safe_ip = target_ip.replace(".", "_")
    # Format the timestamp into YYYYMMDD_HHMMSS
    timestamp = start_time.strftime("%Y%m%d_%H%M%S")
    # Build the output filename string
    filename = f"scan_report_{safe_ip}_{timestamp}.txt"

    # Use try-except to handle filesystem errors cleanly
    try:
        # Open the file in write mode ('w') with UTF-8 encoding using a context manager
        with open(filename, "w", encoding="utf-8") as f:
            # Write report header section
            f.write("=" * 70 + "\n")
            f.write("        XCSA-1100-MC1 NETWORK RECONNAISSANCE SCAN REPORT\n")
            f.write("    Instructor: Hamid Talebi | Student: Alex Terziyski\n")
            f.write("=" * 70 + "\n\n")

            # Write Target Information
            f.write("1. TARGET DETAILS\n")
            f.write("-" * 70 + "\n")
            f.write(f"Target Input     : {target_host}\n")
            f.write(f"Resolved IP      : {target_ip}\n")
            f.write(f"Scan Started     : {start_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Completed   : {end_time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration         : {elapsed_seconds:.2f} seconds\n\n")

            # Write Operating System Information
            f.write("2. OPERATING SYSTEM FINGERPRINT (ICMP TTL HEURISTICS)\n")
            f.write("-" * 70 + "\n")
            f.write(f"Detected OS      : {os_info['os_name']}\n")
            f.write(f"Received TTL     : {os_info['ttl']}\n")
            f.write(f"Baseline TTL     : {os_info['initial_ttl']}\n")
            f.write(f"Router Hops      : {os_info['estimated_hops']}\n\n")

            # Write Geolocation & Network Intelligence
            f.write("3. GEOLOCATION & NETWORK METADATA\n")
            f.write("-" * 70 + "\n")
            f.write(f"Country / City   : {geo_data['country']}, {geo_data['city']}\n")
            f.write(f"ISP Provider     : {geo_data['isp']}\n")
            f.write(f"AS Number        : {geo_data['as']}\n\n")

            # Write Port Scan Results
            f.write("4. OPEN PORTS IDENTIFIED\n")
            f.write("-" * 70 + "\n")
            # If open ports were found, write each one to the report
            if open_ports:
                # Write table column headers
                f.write(f"{'PORT':<8} {'SERVICE'}\n")
                # Write a divider for the table
                f.write(f"{'-'*8} {'-'*50}\n")
                # Loop through each open port entry
                for entry in open_ports:
                    # Write the port number and service description
                    f.write(f"{entry['port']:<8} {entry['service']}\n")
            # If no open ports were found, write a note
            else:
                f.write("No open ports found on target (host may be firewalled).\n")

            # Write closing footer
            f.write("\n" + "=" * 70 + "\n")
            f.write("END OF SCAN REPORT\n")
            f.write("=" * 70 + "\n")

        # Print success confirmation with the filename created
        print(f"[+] Scan report saved successfully to: {filename}")
        # Return the filename string
        return filename

    # Catch IOError if the script lacks permission or disk is full
    except IOError as io_err:
        # Print the error details
        print(f"[-] File I/O Error: Could not save report ({io_err})")
        # Return None
        return None
    # Catch any other file-related exception
    except Exception as err:
        # Print the error details
        print(f"[-] Unexpected error saving file: {err}")
        # Return None
        return None


# Main program function that coordinates the whole scan process
def main():
    # Print a clean, human header banner
    print("=" * 70)
    print(" XCSA-1100-MC1: Network Scanner & OS Fingerprinting Tool")
    print(" Instructor: Hamid Talebi | Student: Alex Terziyski")
    print(" Modules: Sockets | Subprocess | Regex | File I/O | Try-Except | APIs")
    print("=" * 70)

    # Check if a target was passed as a command-line argument: python network_scanner.py <target>
    if len(sys.argv) > 1:
        # Grab the target from sys.argv[1]
        target_input = sys.argv[1]
        # Display the target passed via argument
        print(f"[*] Target provided via command line: {target_input}")
    # Otherwise, ask the user interactively
    else:
        # Use try-except to catch Ctrl+C during input prompt
        try:
            # Prompt the user to type in a hostname or IP address
            target_input = input("\nEnter Target IP or Hostname (e.g., scanme.nmap.org or 127.0.0.1): ")
        # Catch KeyboardInterrupt if user presses Ctrl+C
        except KeyboardInterrupt:
            # Print an exit message
            print("\n[-] Scan cancelled by user.")
            # Exit cleanly
            sys.exit(0)

    # Step 1: Resolve the input into an IPv4 address
    resolved_ip = resolve_target(target_input)
    # If resolution failed, stop execution
    if not resolved_ip:
        # Print exit warning
        print("[-] Exiting: Unable to proceed without a valid IP address.")
        # Exit with a non-zero error code
        sys.exit(1)

    # Record the scan starting time
    start_time = datetime.now()

    # Step 2: Detect the operating system via ICMP ping and TTL regex
    os_info = detect_os(resolved_ip)

    # Step 3: Scan the target's TCP ports using sockets
    open_ports = scan_ports(resolved_ip, COMMON_PORTS)

    # Step 4: Look up IP geolocation via REST API
    geo_data = get_ip_geolocation(resolved_ip)

    # Step 5: Save all findings into a timestamped report file
    report_file = save_report(
        target_host=target_input,
        target_ip=resolved_ip,
        os_info=os_info,
        open_ports=open_ports,
        geo_data=geo_data,
        start_time=start_time
    )

    # Print final summary banner
    print("\n" + "=" * 70)
    print("[*] SCAN COMPLETED SUCCESSFULLY")
    print(f"    - Target IP    : {resolved_ip}")
    print(f"    - Detected OS  : {os_info['os_name']}")
    print(f"    - Open Ports   : {len(open_ports)}")
    print(f"    - Report File  : {report_file}")
    print("=" * 70 + "\n")


# Standard Python execution guard
if __name__ == "__main__":
    # Wrap main in try-except to handle Ctrl+C interrupts gracefully
    try:
        # Run the main function
        main()
    # Catch user pressing Ctrl+C at any point during scan
    except KeyboardInterrupt:
        # Print a clean exit message instead of a scary traceback
        print("\n[-] Scan interrupted by user (Ctrl+C). Exiting cleanly.")
        # Exit with status code 130 (standard SIGINT exit code)
        sys.exit(130)
    # Catch any unhandled exceptions to prevent hard crashes
    except Exception as fatal_error:
        # Print the error details
        print(f"\n[-] Fatal error: {fatal_error}")
        # Exit with error code 1
        sys.exit(1)

