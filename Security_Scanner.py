# Security Scanner Core Logic(Week 1 & 2 Foundation)

# Importing nmap library to launch and read Nmap's output

import nmap
import json
import time

# --- NEW IMPORTS REQUIRED FOR VULNERABILITY API INTEGRATION ---
import requests


class PortScanner:
    """
    CLASS 1: Handles the execution of Nmap scans and the initial data parsing.
    This class is responsible for weel 1 objectives:
        1. Automating the Nmap command
        2. Parsing the complex XML output into a clean Python dictionary structure.
    """

    def __init__(self):
        self.nm = nmap.PortScanner()
    # This Constructor runs when you create a PortScanner object
    # It initializes an instance of the nmap.PortScanner, which is the necessary link
    # between the python script and the installed nmap program

    def _get_common_port_info(self, host, proto, port, port_data):
        """
        [HELPER METHOD] Extracts and cleans up the raw service data for a sinle open port
        """
        Port_data = self.nm[host][proto][port]
        # This function fetches specific data (like service name, product, version, etc.)
        # from the raw, complex scan results provided by the self.nm object

        product = port_data.get('product', '').strip()
        version = port_data.get('version', '').strip()
        name = port_data.get('name', '').strip()
        # it extracts the key fields needed for analysis
        # .get('key', '-') safely returns the value for 'key' or '-' if 'key' is missing

        # Return a neatly organized dictionary for a single port
        return {
            'port_id': port,
            'protocol': proto,
            'state': port_data.get('state', 'unknown'),
            'service_name': name,
            'service_product': product,
            'service_version': version
        }
        # This dictionary structure is easier to work with for further analysis

    def run_scan(self, target_ip, mode='standard', ports=None):
        """
        [MAIN SCAN METHOD] Executes the Nmap scan and returns structured results.

        target_ip: The IP address to scan (e.g., '192.168.1.1').
        mode: The scan mode.
        ports: A single port (e.g., '104') or a range (e.g., '1-1000') to scan.
        """
        print(f"[*] Starting scan on {target_ip} in '{mode}' mode...")

        # --- Week 1 & 3: Defining Scan Arguments (Nmap) command ---
        if mode == 'standard':
            arguments = '-sS -sV -sC -A -T4'
        elif mode == 'privacy':
            arguments = '-sS --top-ports 100 -T2 --max-retries 1'
        else:
            print(f"[!] Invalid scan mode '{mode}'. Using 'standard'.")
            arguments = '-sS -sV -sC -A -T4'

        # --- DYNAMIC PORT SELECTION LOGIC (New/Modified Block) ---
        if ports:
            # If a specific port or range is provided (e.g., '104'), append the -p flag.
            print(f"[*] Limiting scan to port(s): {ports}")

            # This appends the Nmap flag: -p 104
            arguments += f" -p {ports}"
        # --- CORE EXECUTION BLOCK ---
        try:
            # This line runs the nmap program in the background!
            self.nm.scan(hosts=target_ip, arguments=arguments)
        except Exception as e:
            # if Nmap fails (e.g., permission error or not installed), we catch the error
            # and return a dictionary that signals failure
            return {"error": f"nmap scan failed. Check nmap installation guideline (https://nmap.org/book/install.html) and the permissions: {e}"}

        # Check if the host was reached at all
        if target_ip not in self.nm.all_hosts():
            return {"error": f"Host {target_ip} is unreachable or does not exist."}

        # Prepare the final structured dictionary to hold all results
        scan_report = {
            'target': target_ip,
            'status': self.nm[target_ip].state(),  # e.g., 'up' or 'down'
            'ports': []  # This list will hold all the open ports as dictionaries
        }

        # ---Week 1: Parsing the Open Ports
        # Loop1: Iterate over all protocols (tcp, udp, etc.) found on the target
        for proto in self.nm[target_ip].all_protocols():
            # Get a list of all ports for this protocol
            lport = self.nm[target_ip][proto].keys()
            # Loop2: Iterate over each port in the list
            for port in lport:
                # Check if the port is open!
                if self.nm[target_ip][proto][port]['state'] == 'open':
                    # if it's open, use the helper function to get clean data
                    port_data = self._get_common_port_info(
                        target_ip, proto, port,  self.nm[target_ip][proto][port])
                    scan_report['ports'].append(port_data)

            print(
                f"[*] Scan complete for {target_ip}. Found {len(scan_report['ports'])} open ports.")
            return scan_report


class RecommendationEngine:
    """
    class 2:(week 2 logic) Analyzes the clean scan results and provides security recoomendationss.
    This class takes the clean output nfrom the scanner and adds the security intelligence layer.
    """
    # ---The Brain of the scanner: Risk Mapping ---
    STATIC_RISK_MAPPING = {
        # Critical Risks (Clear Test ptotocols, high=risk services)
        # Port 21 (FTP) is often used on imaging devices for file transfer-unencrypted
        21: {'level': 'Critical', 'service': 'FTP', 'recommendation': 'Disable anonymous access. Use SFTP or FTPS instead of cleartext FTP. If on a medical device, ensure access is strictly internal.'},
        23: {'level': 'Critical', 'service': 'Telnet', 'recommendation': 'Telnet is unencrypted. Disable immediately and use SSH (Port 22) instead.'},
        139: {'level': 'Critical', 'service': 'NetBIOS/SMB', 'recommendation': 'Block this port externally. Ensure SMB is patched and configured with strong authentication.'},
        445: {'level': 'Critical', 'service': 'SMB', 'recommendation': 'Block this port externally. SMB (especially v1) is prone to major exploits (e.g., WannaCry).'},

        # Ports common in medical/enterprise environments
        110: {'level': 'Warning', 'service': 'POP3', 'recommendation': 'If used, switch to POP3S (Port 995) for encryption. Unencrypted email protocols are high risk.'},
        25: {'level': 'Warning', 'service': 'SMTP', 'recommendation': 'Ensure this port is strictly protected and not an open relay. Use TLS for all outgoing mail.'},
        161: {'level': 'Warning', 'service': 'SNMP', 'recommendation': 'If SNMP is exposed, ensure V3 is used with strong authentication. V1/V2 typically use clear-text "public" community strings.'},

        # --- ADDITIONS FOR MEDICAL IMAGING DEVICES (DICOM / HL7)
        104: {'level': 'Warning', 'service': 'DICOM', 'recommendation': 'DICOM (port 104) is unencrypted by default. Restrict access to internal networks only. Enforce secure DICOM TLS/VPN for remote access to protect Patient Health Information (PHI).'},
        2575: {'level': 'Warning', 'service': 'HL7/MLLP', 'recommendation': 'HL7 (port 2575) over MLLP is unencrypted. Restrict access to internal systems only. Ensure strong authentication and use a secure tunnel (VPN/TLS) to comply with healthcare data protection standards (e.g., HIPAA).'},
        11112: {'level': 'Warning', 'service': 'DICOM Alternate', 'recommendation': 'This alternate DICOM port is unencrypted by default. Restrict access to internal networks. Use secure DICOM TLS/VPN for any external communication to protect PHI.'},


        # Warning Risks (Standard services that require hardening)
        80: {'level': 'Warning', 'service': 'HTTP', 'recommendation': 'Implement HTTPS (Port 443) encryption. Redirect all HTTP traffic to HTTPS.'},
        22: {'level': 'Warning', 'service': 'SSH', 'recommendation': 'Enforce key-based authentication and disable root login. Ensure software is up-to-date.'},
        3389: {'level': 'Warning', 'service': 'RDP', 'recommendation': 'Restrict RDP access to trusted source IPs or use a VPN. Use complex passwords/MFA.'},
        1433: {'level': 'Warning', 'service': 'MS SQL', 'recommendation': 'Restrict network access. Change default SA password and ensure all accounts use strong passwords.'},

        # Informational (Default Safe services that still need review)
        443: {'level': 'Informational', 'service': 'HTTPS', 'recommendation': 'Ensure SSL/TLS certificates are valid and strong ciphers are enforced.'},
        53: {'level': 'Informational', 'service': 'DNS', 'recommendation': 'If public, ensure it is not configured as an open resolver to prevent amplification attacks.'}
    }
    # --- New Structure: List of known highly vulnerable version strings ---
    CRITICAL_VULNERABLE_VERSIONS = {
        # Examples of Apache versions with known flaws
        'apache': ['2.4.29', '2.4.49', '2.4.50'],
        # Examples of Nginx versions with known flaws
        'nginx': ['1.18.0', '1.20.0', '1.21.0'],
        # Example of a vsftpd version linked to a backdoor
        'vsftpd': ['2.3.4']
    }
    # Placeholder for the actual NVD API endpoint
    NVD_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# The one that you sent me earlier
    NVD_API_KEY = "9e00ee9f-b407-412b-bcd4-87f1d910f103"

    def _fetch_vulnerability_data_live(self, product_name, version):
        """
        [Live API INTEGRATION] Queries an external vulnerability database (NVD) 
        for the given product and version.
        """

        product_lower = product_name.lower()

        # --- Initialize variables to avoid UnboundLocalError ---
        # These variables must be defined before the try block if they are
        # referenced outside of the conditional logic (like in the print statements).
        base_severity = 'N/A'
        description = 'Vulnerability details not available.'
        cve_id = 'N/A'

        # --- STEP 1: ATTEMPT REAL API QUERY
        try:
            query = f"{product_lower} {version}"
            headers = {"apiKey": self.NVD_API_KEY}
            params = {"keywordSearch": query, "resultsPerPage": 3}

            print(f"[*] Fetching NVD data for: {query}...")
            response = requests.get(
                self.NVD_API_ENDPOINT, headers=headers, params=params, timeout=10
            )
            response.raise_for_status()
            data = response.json()

            vulnerabilities = data.get("vulnerabilities", [])

            # --- NVD-Style Response Parsing ---
            if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
                # 1. Access the CVE object inside the first vulnerability entry
                cve_data = vulnerabilities[0].get('cve', {})
                cve_id = cve_data.get('id', 'N/A')

                # 2. Extract Severity
                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v2 = metrics.get("cvssMetricV2", [])

                if cvss_v31:
                    base_severity = cvss_v31[0].get(
                        "cvssData", {}).get("baseSeverity", "N/A")
                elif cvss_v2:
                    # Note: CVSS v2 is often in a flat structure, not nested under cvssData in some feeds
                    base_severity = cvss_v2[0].get("baseSeverity", "N/A")

                # 3. Extract Description
                description = cve_data.get('descriptions', [{}])[0].get(
                    'value', 'Vulnerability details not available.')

                # --- DEBUG PRINT CHECK ---
                print(f"--- PARSING CHECK FOR {product_name} v{version} ---")
                print(f"CVE ID FOUND: {cve_id}")
                print(f"BASE SEVERITY: {base_severity}")
                print(f"DESCRIPTION START: {description[:80]}...")
                print("---------------------------------------")

                # 4. Final Formatting
                if base_severity and base_severity != 'N/A':
                    api_level = base_severity.capitalize()

                    return {
                        "is_vulnerable": True,
                        "cve_id": cve_id,
                        "risk_level": api_level,
                        "description": description
                    }

        except requests.RequestException as e:
            # Handles connection errors, timeouts, or API 4xx/5xx errors.
            print(
                f"[!] Warning: Live vulnerability lookup failed (Connection Error: {e}).")
            return {"is_vulnerable": False,
                    "error_message": f"Live lookup failed due to network or API error: {e}. Check API key and connectivity."}

        # If API call succeeds but finds nothing for this specific version, return false.
        print(f"[*] NVD found no specific CVEs for {product_name} v{version}.")
        return {"is_vulnerable": False}

    def analyze_report(self, scan_report):
        """
        Analyzes the clean scan results and provides security recommendations,
        prioritizing live NVD API data over static mappings.
        """

        if 'error' in scan_report:
            return scan_report

        results = []

        for port_info in scan_report.get('ports', []):
            # 1. Get port and service details
            try:
                port_id = int(port_info['port_id'])
                product = port_info.get('service_product', '').strip()
                version = port_info.get('service_version', '').strip()
                service_name = port_info.get('service_name', '').strip()
                service_name_upper = service_name.upper() or 'UNKNOWN'

            except ValueError:
                continue

            # 2. Define the initial alert based on static risk mapping (AS FALLBACK)
            static_alert = self.STATIC_RISK_MAPPING.get(port_id)

            if static_alert:
                alert_data = static_alert.copy()
            else:
                # --- ULTIMATE GENERIC FALLBACK (The only non-API specific recommendation remaining) ---
                alert_data = {
                    'level': 'Informational',
                    'service': service_name_upper,
                    # *** MODIFIED RECOMMENDATION TEXT ***
                    'recommendation':
                    (
                        f"Action Required: Port {port_id} ({service_name_upper}) is open with no specific CVE found. "
                        f"1. **Audit Necessity**: Verify if this service is absolutely required. "
                        f"2. **Restrict Access**: Implement strict firewall rules to limit connections to trusted internal IPs only. "
                        f"3. **Patch/Update**: Confirm software is running the latest, most secure version."
                    )
                }

            # 3. Determine the best search query for NVD
            search_product = ""
            search_version = ""

            if product:
                search_product = product
                search_version = version
            elif service_name:
                search_product = service_name
                search_version = ""

            # 4. Perform deeper version-based API check (NOW ALWAYS RUNS if a name is found)
            if search_product:
                vulnerability_data = self._fetch_vulnerability_data_live(
                    search_product, search_version)

                if vulnerability_data.get('is_vulnerable'):
                    # NVD FOUND A SPECIFIC VULNERABILITY (CVE-based) -> OVERRIDE ALL STATIC DATA
                    live_level = vulnerability_data.get(
                        'risk_level', alert_data['level'])

                    alert_data['level'] = live_level
                    alert_data['recommendation'] = (
                        f"Vulnerability found: Product: {search_product} v{version or 'Unknown'} is associated with "
                        f"ID: {vulnerability_data.get('cve_id', 'N/A')}. Action: {vulnerability_data['description']}"
                    )

                elif 'error_message' in vulnerability_data:
                    # NVD lookup failed (e.g., API key, connection) - Keep static/default recommendation
                    print(
                        f"[!] Error in NVD lookup for port {port_id}: {vulnerability_data['error_message']}")

            # 5. Compile the final result for this port
            results.append({

                'port': port_id,
                'protocol': port_info['protocol'],
                'service': alert_data['service'],
                'state': port_info['state'],
                'detected_version': version or 'unknown',
                'risk_level': alert_data['level'],
                'recommendation': alert_data['recommendation']
            })

        scan_report['recommendations'] = results
        scan_report['timestamp'] = int(time.time())
        return scan_report


if __name__ == "__main__":
    # The console object (initialized by rich.console.Console) is used for colored printing.
    console.print(
        "\n[bold]--- RUNNING STANDALONE SECURITY SCANNER ---[/bold]")

    # --- 2. GET USER INPUT ---
    # Use input() to manually get the target and port from the user.
    target_ip = input("Enter the target IP address (e.g., 192.168.1.1): ")

    # The ports input should be flexible (e.g., '104' or '1-1000' or left empty)
    specific_ports = input(
        "Enter specific port(s) to scan (e.g., '80', '100-200', or leave blank for common ports): ")

    # Clean up input: set to None if the user leaves it blank
    if not specific_ports.strip():
        specific_ports = None

    # 1. Initialize Components
    scanner = PortScanner()
    engine = RecommendationEngine()

    # 2. Run Scan
    # The run_scan function must be the one I provided previously
    # (with the 'ports' parameter).
    console.print(
        f"[*] Target set to: [cyan]{target_ip}[/cyan], Port(s): [cyan]{specific_ports or 'COMMON'}[/cyan]")

    raw_report = scanner.run_scan(
        target_ip, mode='standard', ports=specific_ports)

    # 3. Handle Errors
    if 'error' in raw_report:
        console.print(
            f"\n[bold red]ERROR[/bold red]: Could not complete scan. {raw_report['error']}")
    else:
        # 4. Analyze and Generate Final Report
        # Ensure 'timestamp' is in the raw_report before analysis if the report generator needs it
        raw_report['timestamp'] = time.time()
        scan_report = engine.analyze_report(raw_report)
        print_formatted_report(scan_report)
