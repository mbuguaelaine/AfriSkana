import nmap
import json
import time

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
    

    def _get_common_port_info(self, host, proto, port, port_data):
        """
        [HELPER METHOD] Extracts and cleans up the raw service data for a sinle open port
        """
        Port_data = self.nm[host][proto][port]
        

        product = port_data.get('product', '').strip()
        version = port_data.get('version', '').strip()
        name = port_data.get('name', '').strip()
        
        return {
            'port_id': port,
            'protocol': proto,
            'state': port_data.get('state', 'unknown'),
            'service_name': name,
            'service_product': product,
            'service_version': version
        }
        

    def run_scan(self, target_ip, mode='standard', ports=None):
        """
        [MAIN SCAN METHOD] Executes the Nmap scan and returns structured results.

        target_ip: The IP address to scan (e.g., '192.168.1.1').
        mode: The scan mode.
        ports: A single port (e.g., '104') or a range (e.g., '1-1000') to scan.
        """
        print(f"[*] Starting scan on {target_ip} in '{mode}' mode...")

        
        if mode == 'standard':
            arguments = '-sS -sV -sC -T4'
        elif mode == 'privacy': 
            arguments = '-sT --top-ports 1000 -T4 --version-light'

        else:
            print(f"[!] Invalid scan mode '{mode}'. Using 'standard'.")
            arguments = '-sS -sV -sC -T4'

        
        if ports:
            
            print(f"[*] Limiting scan to port(s): {ports}")

            
            arguments += f" -p {ports}"
        
        try:
            
            self.nm.scan(hosts=target_ip, arguments=arguments)
        except Exception as e:
            
            return {"error": f"nmap scan failed. Check nmap installation guideline (https://nmap.org/book/install.html) and the permissions: {e}"}

        
        if target_ip not in self.nm.all_hosts():
            return {"error": f"Host {target_ip} is unreachable or does not exist."}

        
        scan_report = {
            'target': target_ip,
            'status': self.nm[target_ip].state(), 
            'ports': []  
        }

        
        for proto in self.nm[target_ip].all_protocols():
            
            lport = self.nm[target_ip][proto].keys()
            
            for port in lport:
                
                if self.nm[target_ip][proto][port]['state'] == 'open':
                    
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
    
    STATIC_RISK_MAPPING = {
        
        21: {'level': 'Critical', 'service': 'FTP', 'recommendation': 'Disable anonymous access. Use SFTP or FTPS instead of cleartext FTP. If on a medical device, ensure access is strictly internal.'},
        23: {'level': 'Critical', 'service': 'Telnet', 'recommendation': 'Telnet is unencrypted. Disable immediately and use SSH (Port 22) instead.'},
        139: {'level': 'Critical', 'service': 'NetBIOS/SMB', 'recommendation': 'Block this port externally. Ensure SMB is patched and configured with strong authentication.'},
        445: {'level': 'Critical', 'service': 'SMB', 'recommendation': 'Block this port externally. SMB (especially v1) is prone to major exploits (e.g., WannaCry).'},

        
        110: {'level': 'Warning', 'service': 'POP3', 'recommendation': 'If used, switch to POP3S (Port 995) for encryption. Unencrypted email protocols are high risk.'},
        25: {'level': 'Warning', 'service': 'SMTP', 'recommendation': 'Ensure this port is strictly protected and not an open relay. Use TLS for all outgoing mail.'},
        161: {'level': 'Warning', 'service': 'SNMP', 'recommendation': 'If SNMP is exposed, ensure V3 is used with strong authentication. V1/V2 typically use clear-text "public" community strings.'},

        
        104: {'level': 'Warning', 'service': 'DICOM', 'recommendation': 'DICOM (port 104) is unencrypted by default. Restrict access to internal networks only. Enforce secure DICOM TLS/VPN for remote access to protect Patient Health Information (PHI).'},
        2575: {'level': 'Warning', 'service': 'HL7/MLLP', 'recommendation': 'HL7 (port 2575) over MLLP is unencrypted. Restrict access to internal systems only. Ensure strong authentication and use a secure tunnel (VPN/TLS) to comply with healthcare data protection standards (e.g., HIPAA).'},
        11112: {'level': 'Warning', 'service': 'DICOM Alternate', 'recommendation': 'This alternate DICOM port is unencrypted by default. Restrict access to internal networks. Use secure DICOM TLS/VPN for any external communication to protect PHI.'},


        
        80: {'level': 'Warning', 'service': 'HTTP', 'recommendation': 'Implement HTTPS (Port 443) encryption. Redirect all HTTP traffic to HTTPS.'},
        22: {'level': 'Warning', 'service': 'SSH', 'recommendation': 'Enforce key-based authentication and disable root login. Ensure software is up-to-date.'},
        3389: {'level': 'Warning', 'service': 'RDP', 'recommendation': 'Restrict RDP access to trusted source IPs or use a VPN. Use complex passwords/MFA.'},
        1433: {'level': 'Warning', 'service': 'MS SQL', 'recommendation': 'Restrict network access. Change default SA password and ensure all accounts use strong passwords.'},

        
        443: {'level': 'Informational', 'service': 'HTTPS', 'recommendation': 'Ensure SSL/TLS certificates are valid and strong ciphers are enforced.'},
        53: {'level': 'Informational', 'service': 'DNS', 'recommendation': 'If public, ensure it is not configured as an open resolver to prevent amplification attacks.'}
    }
    
    CRITICAL_VULNERABLE_VERSIONS = {
        
        'apache': ['2.4.29', '2.4.49', '2.4.50'],
        
        'nginx': ['1.18.0', '1.20.0', '1.21.0'],
        
        'vsftpd': ['2.3.4']
    }
    
    NVD_API_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    NVD_API_KEY = "9e00ee9f-b407-412b-bcd4-87f1d910f103"

    def _fetch_vulnerability_data_live(self, product_name, version):
        """
        [Live API INTEGRATION] Queries an external vulnerability database (NVD) 
        for the given product and version.
        """

        product_lower = product_name.lower()

        
        base_severity = 'N/A'
        description = 'Vulnerability details not available.'
        cve_id = 'N/A'

        
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

            
            if isinstance(vulnerabilities, list) and len(vulnerabilities) > 0:
               
                cve_data = vulnerabilities[0].get('cve', {})
                cve_id = cve_data.get('id', 'N/A')

               
                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                cvss_v2 = metrics.get("cvssMetricV2", [])

                if cvss_v31:
                    base_severity = cvss_v31[0].get(
                        "cvssData", {}).get("baseSeverity", "N/A")
                elif cvss_v2:
                    
                    base_severity = cvss_v2[0].get("baseSeverity", "N/A")

               
                description = cve_data.get('descriptions', [{}])[0].get(
                    'value', 'Vulnerability details not available.')

                
                print(f"--- PARSING CHECK FOR {product_name} v{version} ---")
                print(f"CVE ID FOUND: {cve_id}")
                print(f"BASE SEVERITY: {base_severity}")
                print(f"DESCRIPTION START: {description[:80]}...")
                print("---------------------------------------")

                
                if base_severity and base_severity != 'N/A':
                    api_level = base_severity.capitalize()

                    return {
                        "is_vulnerable": True,
                        "cve_id": cve_id,
                        "risk_level": api_level,
                        "description": description
                    }

        except requests.RequestException as e:
            
            print(
                f"[!] Warning: Live vulnerability lookup failed (Connection Error: {e}).")
            return {"is_vulnerable": False,
                    "error_message": f"Live lookup failed due to network or API error: {e}. Check API key and connectivity."}

        
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
           
            try:
                port_id = int(port_info['port_id'])
                product = port_info.get('service_product', '').strip()
                version = port_info.get('service_version', '').strip()
                service_name = port_info.get('service_name', '').strip()
                service_name_upper = service_name.upper() or 'UNKNOWN'

            except ValueError:
                continue

            
            static_alert = self.STATIC_RISK_MAPPING.get(port_id)

            if static_alert:
                alert_data = static_alert.copy()
            else:
                
                alert_data = {
                    'level': 'Informational',
                    'service': service_name_upper,
                    
                    'recommendation':
                    (
                        f"Action Required: Port {port_id} ({service_name_upper}) is open with no specific CVE found. "
                        f"1. **Audit Necessity**: Verify if this service is absolutely required. "
                        f"2. **Restrict Access**: Implement strict firewall rules to limit connections to trusted internal IPs only. "
                        f"3. **Patch/Update**: Confirm software is running the latest, most secure version."
                    )
                }

            
            search_product = ""
            search_version = ""

            if product:
                search_product = product
                search_version = version
            elif service_name:
                search_product = service_name
                search_version = ""

            
            if search_product:
                vulnerability_data = self._fetch_vulnerability_data_live(
                    search_product, search_version)

                if vulnerability_data.get('is_vulnerable'):
                    
                    live_level = vulnerability_data.get(
                        'risk_level', alert_data['level'])

                    alert_data['level'] = live_level
                    alert_data['recommendation'] = (
                        f"Vulnerability found: Product: {search_product} v{version or 'Unknown'} is associated with "
                        f"ID: {vulnerability_data.get('cve_id', 'N/A')}. Action: {vulnerability_data['description']}"
                    )

                elif 'error_message' in vulnerability_data:
                    
                    print(
                        f"[!] Error in NVD lookup for port {port_id}: {vulnerability_data['error_message']}")

            
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

