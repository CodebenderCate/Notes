## **Features**
### 1. **Automated Tool Setup**
- Installs categorized cybersecurity tools:
  - Recon, OSINT, Web security, Post-exploitation, Reverse engineering, etc.
- Logs errors and provides a summary of failed installs.
---
## **Categorized Tool Installation**: Installs cybersecurity tools grouped by purpose
#### Reconnaissance
- [nmap](https://nmap.org) - Host discovery and port scanning.
- [nikto](https://cirt.net/Nikto2) – Web server vulnerability scanner.
- [metasploit-framework](https://www.metasploit.com) – Penetration testing framework.
- [burpsuite](https://portswigger.net/burp) – Web proxy and vulnerability scanner.
- [zaproxy](https://www.zaproxy.org) – Web app security scanner.
- [theharvester](https://github.com/laramies/theHarvester) – OSINT for emails, domains, and IPs.
- [recon-ng](https://github.com/lanmaster53/recon-ng) – OSINT automation.
- [amass](https://github.com/OWASP/Amass) – Subdomain enumeration.
- [whatweb](https://github.com/urbanadventurer/WhatWeb) – Web fingerprinting.
#### Open Source Intelligence (OSINT)
- [sherlock](https://github.com/sherlock-project/sherlock) – Username search across social networks.
- [metagoofil](https://github.com/laramies/metagoofil) – Metadata scraper from docs.
- [shodan](https://www.shodan.io) – Search engine for connected devices.
- [dnsrecon](https://github.com/darkoperator/dnsrecon) – DNS records enumeration.
- [dnsenum](https://github.com/fwaeytens/dnsenum) – Multithreaded DNS recon.
#### Web Application Security
- [sqlmap](https://sqlmap.org) – Automated SQL injection tool.
- [xsstrike](https://github.com/s0md3v/XSStrike) – Advanced XSS detection.
- [wapiti](https://github.com/wapiti-scanner/wapiti) – Web app scanner.
- [commix](https://github.com/commixproject/commix) – Command injection exploit tool.
#### Password and Authentication Cracking
- [john](https://www.openwall.com/john/) – Versatile password cracker.
- [hashcat](https://hashcat.net/hashcat/) – High-performance password recovery.
- [hydra](https://github.com/vanhauser-thc/thc-hydra) – Login brute-force tool.
- [pdfcrack](https://www.kali.org/tools/pdfcrack/) – PDF password recovery.
- [steghide](https://www.kali.org/tools/steghide/) – Steganography tool.
#### Network Analysis and Traffic Monitoring
- [wireshark](https://www.wireshark.org) – Packet analyzer.
- [tcpdump](https://www.tcpdump.org) – CLI-based packet sniffer.
- [ettercap](https://www.ettercap-project.org) – Network MITM tool.
- [aircrack-ng](https://www.aircrack-ng.org) – WiFi auditing suite.
#### Binary and Malware Analysis
- [radare2](https://rada.re/n/) – Reverse engineering framework.
- [binwalk](https://github.com/ReFirmLabs/binwalk) – Firmware analyzer.
- [yara](https://virustotal.github.io/yara/) – Pattern matching for malware.
- [strings](https://man7.org/linux/man-pages/man1/strings.1.html) – Extract printable strings.
- [ghidra](https://ghidra-sre.org/) – NSA’s SRE framework. Now enhanced with **AI (Mistral)** for function renaming.
#### Exploitation Frameworks and Tools
- [exploitdb](https://www.exploit-db.com) – Exploit archive.
- [impacket-scripts](https://github.com/SecureAuthCorp/impacket) – Python tools for networking.
- [empire](https://github.com/BC-SECURITY/Empire) – Post-exploitation/C2.
- [mimikatz](https://github.com/gentilkiwi/mimikatz) – Credential extraction.
- [bloodhound](https://github.com/BloodHoundAD/BloodHound) – AD enumeration.
#### Post-Exploitation and Forensics
- [volatility](https://www.volatilityfoundation.org) – Memory forensics.
- [autopsy](https://www.sleuthkit.org/autopsy/) – Full digital forensics toolkit.
#### Social Engineering
- [set](https://github.com/trustedsec/social-engineer-toolkit) – SE attacks & payloads.
- [beef-xss](https://github.com/beefproject/beef) – Browser hook & control.
#### Wireless and IoT Security
- [wifite](https://github.com/derv82/wifite2) – Automated WiFi attacks.
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x) – WPS brute-force.
#### Utility and Maintenance Tools
- [postman](https://www.postman.com) – API testing GUI.
- [netcat](https://nc110.sourceforge.io) – Swiss army knife of networking.
- [socat](http://www.dest-unreach.org/socat/) – Bi-directional data relay.
- [gobuster](https://github.com/OJ/gobuster) – Directory & DNS brute-forcing.
- [trivy](https://github.com/aquasecurity/trivy) – Container vulnerability scanner.
- [scoutsuite](https://github.com/nccgroup/ScoutSuite) – Cloud security assessment.
- [rkhunter](https://rkhunter.sourceforge.net) – Rootkit detector.
- [chkrootkit](http://www.chkrootkit.org) – Local rootkit scanner.
#### Development Utilities
- [python3](https://www.python.org) – Main scripting language.
- [ruby](https://www.ruby-lang.org) – Flexible scripting for exploits.
- [golang](https://golang.org) – Static compiled toolkits.
- [jq](https://stedolan.github.io/jq/) – JSON processor.
- [tmux](https://github.com/tmux/tmux/wiki) – Terminal multiplexer.
- [exiftool](https://exiftool.org) – Metadata extractor.
---
# The Script
```python
#!/usr/bin/env python3
import subprocess
import logging
import os
import time
from typing import List, Dict

# === Config ===
LOG_FILE = "install_errors.log"
RETRY_COUNT = 3
RETRY_DELAY = 5     # seconds between retries
INSTALL_TIMEOUT = 900  # seconds per apt call
APT_OPTIONS = "--no-install-recommends -y"

# === Logging ===
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR, format='%(asctime)s - %(levelname)s - %(message)s')

# === Helpers ===
def run_command(cmd: str, timeout: int = INSTALL_TIMEOUT) -> subprocess.CompletedProcess:
    """
    Run a shell command, return CompletedProcess. Do not raise on non-zero.
    """
    try:
        print(f"Running: {cmd}")
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        if proc.returncode != 0:
            logging.error(f"Command failed: {cmd}\nreturncode: {proc.returncode}\nstdout:\n{proc.stdout}\nstderr:\n{proc.stderr}")
        return proc
    except subprocess.TimeoutExpired as e:
        logging.error(f"TimeoutExpired for: {cmd}\n{e}")
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=f"Timeout after {timeout}s")
    except Exception as e:
        logging.error(f"Unexpected error running command: {cmd}\n{e}")
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr=str(e))

def apt_install(pkg: str) -> bool:
    """
    Attempt to install a package via apt-get with retries.
    Returns True on success, False on failure.
    """
    for attempt in range(1, RETRY_COUNT + 1):
        cmd = f"apt-get install {APT_OPTIONS} {pkg}"
        proc = run_command(cmd)
        if proc.returncode == 0:
            return True
        print(f"[WARN] Install failed for {pkg} (attempt {attempt}/{RETRY_COUNT}).")
        if attempt < RETRY_COUNT:
            time.sleep(RETRY_DELAY)
    return False

def install_packages(package_list: List[str]) -> List[str]:
    """
    Install packages from list. Return list of failed package names.
    """
    failed = []
    for package in package_list:
        package = package.strip()
        if not package:
            continue
        print(f"Installing: {package}")
        success = apt_install(package)
        if not success:
            failed.append(package)
    return failed

# === Root check and preflight update ===
def preflight():
    if os.geteuid() != 0:
        raise SystemExit("This script must be run as root. Use sudo.")
    # Update package lists before installing
    proc = run_command("apt-get update --allow-releaseinfo-change")
    if proc.returncode != 0:
        print("[WARN] apt-get update returned non-zero. Continuing but installs may fail. Check logs.")

# === Package lists (deduplicated, normalized where reasonable) ===
def main():
    preflight()

    essential_tools = ["wget", "curl", "gnupg", "software-properties-common"]

    # Primary tools grouped by category.
    tools = {
        "Reconnaissance": [
            "nmap", "nikto", "metasploit-framework", "burpsuite", "zaproxy",
            "theharvester", "recon-ng", "amass", "whatweb", "masscan", "ffuf"
        ],
        "OSINT": [
            "sherlock", "metagoofil", "shodan", "dnsrecon", "dnsenum"
        ],
        "Web Application Security": [
            "sqlmap", "xsstrike", "wapiti", "commix"  # ffuf already in Recon
        ],
        "Password Cracking": [
            "john", "hashcat", "hydra", "pdfcrack", "steghide"
        ],
        "Network Analysis": [
            "wireshark", "tcpdump", "ettercap", "aircrack-ng",
            "bettercap", "mitmproxy", "responder"
        ],
        "Binary and Malware Analysis": [
            "radare2", "binwalk", "strings", "yara", "ghidra", "frida"
        ],
        "Exploitation": [
            "exploitdb", "impacket-scripts", "empire", "mimikatz", "bloodhound", "crackmapexec"
        ],
        "Post-Exploitation": [
            "volatility", "autopsy", "pwncat", "smbmap"
        ],
        "Social Engineering": [
            "set", "beef-xss"
        ],
        "Utility Tools": [
            "postman", "wifite", "reaver", "netcat", "socat", "gobuster",
            "trivy", "scoutsuite", "rkhunter", "chkrootkit"
        ],
        "Development Utilities": [
            "python3", "ruby", "golang", "jq", "tmux", "exiftool", "gdb"
        ]
    }

    # Track failures per category
    all_failures: Dict[str, List[str]] = {}

    # Install essentials first
    print("\nInstalling essential utilities...")
    failed_essentials = install_packages(essential_tools)
    if failed_essentials:
        all_failures["Essentials"] = failed_essentials

    # Category installs
    for category, pkg_list in tools.items():
        print(f"\nInstalling {category} tools...")
        # remove duplicates within the list
        unique_pkgs = []
        seen = set()
        for p in pkg_list:
            low = p.lower()
            if low not in seen:
                seen.add(low)
                unique_pkgs.append(p)
        failed = install_packages(unique_pkgs)
        if failed:
            all_failures[category] = failed

    # Summary
    if all_failures:
        print("\n[SUMMARY] Some packages failed to install. See log and summary below.")
        for cat, failed in all_failures.items():
            print(f"{cat}: {', '.join(failed)}")
        logging.error(f"Install summary failures: {all_failures}")
    else:
        print("\n[INFO] All requested tools installed successfully (or apt reported success).")

if __name__ == "__main__":
    main()
```
## Tools Difficult to Install on Kali and Their Alternatives
---
1. **Metasploit Framework**  
   - **Description:** One of the most popular penetration testing and exploitation frameworks.  
   - **Why It's Difficult:** Pre-installed on Kali, but advanced modules can require manual installation or additional dependencies.  
   - **Installation Alternative:**  
     ```bash
     curl https://raw.githubusercontent.com/rapid7/metasploit-framework/master/scripts/msfupdate | bash
     ```
   - **Best OS:** Kali for default setup; Ubuntu for more controlled installations.
---
2. **Cobalt Strike**  
   - **Description:** A powerful adversary simulation tool used for red team exercises.  
   - **Why It's Difficult:** Requires a license and is not open-source.  
   - **Installation Alternative:** Requires a valid license.
     ```bash
     wget <download-link-from-cobalt-strike-license-provider>
     chmod +x cobaltstrike.sh
     ./cobaltstrike.sh
     ```
   - **Best OS:** Kali, Ubuntu, or CentOS.
---
3. **EyeWitness**  
   - **Description:** A tool for capturing website screenshots and metadata during recon.  
   - **Why It's Difficult:** Dependencies often fail on Kali due to Python version conflicts.  
   - **Installation Alternative:**
     ```bash
     sudo apt install python3-venv
     git clone https://github.com/FortyNorthSecurity/EyeWitness.git
     cd EyeWitness/Python
     python3 -m venv venv
     source venv/bin/activate
     pip install -r requirements.txt
     ./EyeWitness.py
     ```
   - **Best OS:** Ubuntu or Parrot OS.
---
4. **Powershell Empire**  
   - **Description:** A post-exploitation framework for red teaming.  
   - **Why It's Difficult:** Outdated support on Kali Linux, and Python dependencies break often.  
   - **Installation Alternative:**
     ```bash
     sudo apt install docker.io
     git clone https://github.com/BC-SECURITY/Empire.git
     cd Empire
     docker build -t empire .
     docker run -it empire
     ```
   - **Best OS:** Windows Subsystem for Linux (WSL) or Parrot OS.
---
5. **BloodHound (Advanced Installation)**  
   - **Description:** Active Directory enumeration tool for red and blue teams.  
   - **Why It's Difficult:** Neo4j database dependencies often cause problems on Kali.  
   - **Installation Alternative:**
     ```bash
     sudo apt install docker.io
     docker pull specterops/bloodhound
     docker run -d -p 7474:7474 -p 7687:7687 specterops/bloodhound
     ```
   - **Best OS:** Ubuntu or Windows for GUI setup.
---
6. **Responder (Advanced Functionality)**  
   - **Description:** Tool for capturing NTLM hashes in a network environment.  
   - **Why It's Difficult:** Core functionality is limited without specific Active Directory environments.  
   - **Installation Alternative:** Available on Kali by default, but advanced setup may require Windows.  
   - **Best OS:** Kali or Windows.
---
7. **King Phisher**  
   - **Description:** Phishing campaign toolkit.  
   - **Why It's Difficult:** Requires significant dependency setup and manual adjustments on Kali.  
   - **Installation Alternative:**
     ```bash
     sudo apt-get install python3 python3-pip
     git clone https://github.com/rsmusllp/king-phisher.git
     cd king-phisher
     sudo ./install.sh
     ```
   - **Best OS:** Ubuntu or Debian.
---
8. **Sn1per (Advanced Edition)**  
   - **Description:** An automated penetration testing framework.  
   - **Why It's Difficult:** Community edition works on Kali, but advanced/pro editions require licensed access.  
   - **Installation Alternative (Community Version):**
     ```bash
     git clone https://github.com/1N3/Sn1per.git
     cd Sn1per
     bash install.sh
     ```
   - **Best OS:** Kali for community edition; licensed pro works best on Ubuntu.
---
9. **Recon-Dog**  
   - **Description:** Lightweight OSINT tool for reconnaissance.  
   - **Why It's Difficult:** Dependency management is easier on non-Kali Linux distributions.  
   - **Installation Alternative:**
     ```bash
     git clone https://github.com/s0md3v/ReconDog.git
     cd ReconDog
     python3 recon.py
     ```
   - **Best OS:** Ubuntu or Parrot OS.
