import requests
from prettytable import PrettyTable
from colorama import Fore, Back, Style, init

# Initialize colorama for terminal colors
init(autoreset=True)


# --------------------------------------
# ASCII Art Banner with Your Name
# --------------------------------------
BANNER = f"""
{Fore.GREEN}
███╗░░░███╗██╗████████╗██████╗░███████╗  ░█████╗░████████╗████████╗░█████╗░░█████╗░██╗░░██╗
████╗░████║██║╚══██╔══╝██╔══██╗██╔════╝  ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔══██╗██║░██╔╝
██╔████╔██║██║░░░██║░░░██████╔╝█████╗░░  ██║░░╚═╝░░░██║░░░░░░██║░░░██║░░██║██║░░╚═╝█████═╝░
██║╚██╔╝██║██║░░░██║░░░██╔══██╗██╔══╝░░  ██║░░██╗░░░██║░░░░░░██║░░░██║░░██║██║░░██╗██╔═██╗░
██║░╚═╝░██║██║░░░██║░░░██║░░██║███████╗  ╚█████╔╝░░░██║░░░░░░██║░░░╚█████╔╝╚█████╔╝██║░╚██╗
╚═╝░░░░░╚═╝╚═╝░░░╚═╝░░░╚═╝░░╚═╝╚══════╝  ░╚════╝░░░░╚═╝░░░░░░╚═╝░░░░╚════╝░░╚════╝░╚═╝░░╚═╝
{Fore.YELLOW}
➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖
{Fore.CYAN}Developed by: {Fore.MAGENTA}Syed Ghufran Raza
{Fore.CYAN}GitHub: {Fore.WHITE}https://github.com/SyedGhufranRaza
{Fore.YELLOW}➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖➖
"""

# --------------------------------------
# API Configuration
# --------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
OTX_API = "https://otx.alienvault.com/api/v1/indicators/cve/{cve_id}/general"

# --------------------------------------
# Helper Functions
# --------------------------------------
def get_cve_details(cve_id):
    """Fetch CVE details from NVD API."""
    try:
        response = requests.get(NVD_API.format(cve_id=cve_id))
        response.raise_for_status()
        data = response.json()
        
        if not data.get("vulnerabilities"):
            return None, None, None
        
        cve_data = data["vulnerabilities"][0]["cve"]
        description = cve_data["descriptions"][0]["value"]
        
        # Extract CVSS details
        cvss_metrics = cve_data.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
        cvss_score = cvss_metrics.get("baseScore", "N/A")
        cvss_vector = cvss_metrics.get("vectorString", "N/A")
        
        return description, cvss_score, cvss_vector
    except Exception as e:
        return None, None, None

def map_to_mitre(description):
    """Map CVE to MITRE techniques."""
    keyword_to_technique = {
        "remote code execution": "T1190",
        "privilege escalation": "T1068",
        "credential dumping": "T1003",
        "phishing": "T1566",
        "pass the hash": "T1550",
        "lateral movement": "T1021",
        "sql injection": "T1190",
        "buffer overflow": "T1200",
    }
    description_lower = description.lower()
    for keyword, technique in keyword_to_technique.items():
        if keyword in description_lower:
            return technique
    return "T1190"

def get_threat_actors(cve_id):
    """Fetch threat actors."""
    try:
        response = requests.get(OTX_API.format(cve_id=cve_id))
        data = response.json()
        return [pulse["name"] for pulse in data.get("pulses", [])][:3] or ["Unknown"]
    except:
        return ["Unknown"]

def get_mitigations(technique_id):
    """Return mitigations for MITRE techniques."""
    mitigations = {
        "T1190": ["Patch public-facing apps", "Enable WAF", "Network segmentation"],
        "T1068": ["Least privilege access", "Disable unnecessary services"],
        "T1003": ["Credential Guard (Windows)", "Monitor LSASS"],
        "T1566": ["Phishing training", "Email filtering"],
        "T1550": ["Restrict NTLM", "Monitor for PtH attacks"],
        "T1021": ["Disable SMBv1", "Network segmentation"],
        "T1200": ["Memory-safe coding", "Input validation"],
    }
    return mitigations.get(technique_id, ["Regular updates", "Monitor logs"])

# --------------------------------------
# Main Tool
# --------------------------------------
def main():
    print(BANNER)
    
    cve_id = input(f"{Fore.CYAN}Enter CVE ID (e.g., CVE-2021-44228): {Fore.WHITE}").strip().upper()
    
    description, cvss_score, cvss_vector = get_cve_details(cve_id)
    if not description:
        print(f"\n{Fore.RED}❌ Error: CVE {cve_id} not found.{Fore.RESET}")
        return
    
    technique_id = map_to_mitre(description)
    mitigations = get_mitigations(technique_id)
    threat_actors = get_threat_actors(cve_id)
    
    table = PrettyTable()
    table.field_names = ["Field", "Details"]
    table.align["Field"] = "l"
    table.align["Details"] = "l"
    table.max_width["Details"] = 50
    
    table.add_row(["CVE ID", cve_id])
    table.add_row(["Description", description])
    table.add_row(["CVSS Score", f"{cvss_score}/10"])
    table.add_row(["CVSS Vector", cvss_vector])
    table.add_row(["MITRE Technique", technique_id])
    table.add_row(["Threat Actors", "\n".join(threat_actors)])
    table.add_row(["Mitigations", "\n→ " + "\n→ ".join(mitigations)])
    
    print("\n" + "=" * 70)
    print(f"{Fore.YELLOW}🔍 MITRE ATT&CK Analysis for {cve_id}")
    print("=" * 70)
    print(table)
    print("=" * 70)
    
    # Closing credits
    print(f"\n{Fore.CYAN}Tool developed by {Fore.MAGENTA}Syed Ghufran Raza")
    print(f"{Fore.YELLOW}🌟 Thanks for using the MITRE ATT&CK Mapper! 🌟")
    print(f"{Fore.CYAN}Contribute at: {Fore.WHITE}https://github.com/SyedGhufranRaza\n")

if __name__ == "__main__":
    main()