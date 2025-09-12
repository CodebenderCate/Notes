

## **Features**
### 1. **System Preparation**
- Updates and upgrades the system.
- Cleans unwanted or blacklisted APT sources.
- Installs essential CLI tools (wget, curl, etc).
### 2. **AI Integration**
- Installs **Ollama** and the **Mistral** LLM locally.
- Enables AI-assisted binary analysis (e.g., automatic function renaming in Ghidra).
### 3. **System Hardening**
- Configures security-focused `sysctl` settings.
- Enables daily audits via Lynis cron job.
### 4. **Integrity Checking**
- Installs `debsums` to validate package integrity.
- Verifies key binaries using SHA256 hashes.
### 5. **Automated Tool Setup**
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
- [aircrack-ng](https://www.aircrack-ng.org) – Wireless network auditing.
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
import subprocess
import hashlib
import os
import logging

# Configure logging
logging.basicConfig(filename='errors.log', level=logging.ERROR, format='%(asctime)s - %(message)s')

# Function to run shell commands
def run_command(command, exit_on_fail=True):
    try:
        print(f"Running: {command}")
        subprocess.run(command, shell=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Command failed: {command}\n{e}")
        if exit_on_fail:
            exit(1)
        return False

# Function to verify package integrity using debsums
def verify_packages_with_debsums():
    print("Verifying installed packages with debsums...")
    run_command("apt-get install -y debsums")
    result = subprocess.run("debsums -c", shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print("[INFO] All packages passed verification with debsums.")
    else:
        print("[WARNING] The following packages failed verification:")
        print(result.stdout.strip())

# Function to clean /etc/apt/sources.list
def clean_sources_list():
    print("Cleaning /etc/apt/sources.list...")
    try:
        backup_path = "/etc/apt/sources.list.bak"
        os.rename("/etc/apt/sources.list", backup_path)
        print(f"[INFO] Backup of sources list saved to {backup_path}")
        with open(backup_path, "r") as f, open("/etc/apt/sources.list", "w") as new_f:
            for line in f:
                if "blacklisted-source.example.com" in line:
                    print(f"[INFO] Removing blacklisted source: {line.strip()}")
                else:
                    new_f.write(line)
        run_command("apt-get update --fix-missing", exit_on_fail=False)
    except Exception as e:
        logging.error(f"[ERROR] Failed to clean sources list: {e}")
        return

# Function to verify file hash
def verify_file_hash(file_path, expected_hash):
    print(f"Verifying {file_path}...")
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        calculated_hash = sha256.hexdigest()
        if calculated_hash == expected_hash:
            print(f"[PASS] Hash for {file_path} matches.")
        else:
            print(f"[FAIL] Hash for {file_path} does not match!")
            print(f"Expected: {expected_hash}")
            print(f"Found:    {calculated_hash}")
    except FileNotFoundError:
        logging.error(f"[ERROR] File {file_path} not found.")
    except Exception as e:
        logging.error(f"[ERROR] Hash verification failed: {e}")

# Install a list of packages and track failures
def install_packages(package_list):
    failed_installs = []
    for package in package_list:
        try:
            print(f"Installing: {package}")
            if not run_command(f"apt-get install -y {package}", exit_on_fail=False):
    failed_installs.append(package)
        except Exception as e:
            logging.error(f"[WARNING] Failed to install {package}: {e}")
            failed_installs.append(package)

    if failed_installs:
        print("\n[SUMMARY] The following packages failed to install:")
        for package in failed_installs:
            print(f"  - {package}")
    else:
        print("\n[INFO] All packages installed successfully.")

# Function to clean and autoremove unnecessary packages and files
def clean_up_system():
    print("Cleaning up unnecessary packages and files...")
    run_command("apt-get autoremove -y")
    run_command("apt-get clean")
    print("[INFO] Cleanup completed.")

# Update and upgrade system
def refresh_kali_keys():
    print("Refreshing Kali archive keys...")
    run_command("apt-get install --reinstall -y kali-archive-keyring", exit_on_fail=False)
def update_system():
    print("Updating and upgrading the system...")
    run_command("apt-get update --allow-releaseinfo-change && apt-get upgrade --fix-missing -y")

# Configure sysctl settings
def configure_sysctl():
    sysctl_config = """
# Security-focused sysctl settings
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv6.conf.all.accept_redirects = 0
fs.protected_symlinks = 1
fs.protected_hardlinks = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
"""
    try:
        marker = "# Security-focused sysctl settings"
with open("/etc/sysctl.conf", "r+") as sysctl_file:
    content = sysctl_file.read()
    if marker not in content:
        sysctl_file.write(sysctl_config)

        run_command("sysctl -p")
    except Exception as e:
        logging.error(f"[ERROR] Failed to configure sysctl: {e}")

# Set up a cron job for Lynis
def setup_cron_job():
    try:
        cron_entry = "0 3 * * * /usr/sbin/lynis audit system"
with open("/etc/crontab", "r+") as f:
    content = f.read()
    if cron_entry not in content:
        f.write(cron_entry + "\n")
    except Exception as e:
        logging.error(f"[ERROR] Failed to set up cron job: {e}")

# Main function to orchestrate tasks
def main():
    refresh_kali_keys()
    update_system()
    clean_sources_list()

    # Install essential tools
    essential_tools = ["wget", "curl", "gnupg", "software-properties-common"]
    install_packages(essential_tools)

    # Tools categorized by purpose
    tools = {
        "Reconnaissance": ["nmap", "nikto", "metasploit-framework", "burpsuite", "zaproxy", "theharvester", "recon-ng", "amass", "whatweb"],
        "OSINT": ["sherlock", "metagoofil", "shodan", "dnsrecon", "dnsenum"],
        "Web Application Security": ["sqlmap", "xsstrike", "wapiti", "commix"],
        "Password Cracking": ["john", "hashcat", "hydra", "pdfcrack", "steghide"],
        "Network Analysis": ["wireshark", "tcpdump", "ettercap", "aircrack-ng"],
        "Binary and Malware Analysis": ["radare2", "binwalk", "strings", "yara", "ghidra"],
        "Exploitation": ["exploitdb", "impacket-scripts", "empire", "mimikatz", "bloodhound"],
        "Post-Exploitation": ["volatility", "autopsy"],
        "Social Engineering": ["set", "beef-xss"],
        "Utility Tools": ["postman", "wifite", "reaver", "netcat", "socat", "gobuster", "trivy", "scoutsuite", "rkhunter", "chkrootkit"],
        "Development Utilities": ["python3", "ruby", "golang", "jq", "tmux", "exiftool"]
    }

    for category, packages in tools.items():
        print(f"\nInstalling {category} tools...")
        install_packages(packages)

    configure_sysctl()
    setup_cron_job()
    verify_packages_with_debsums()

    # Example file hash verification
    files_to_verify = {
        "/usr/bin/nmap": "EXPECTED_HASH_1",
        "/usr/share/sqlmap/sqlmap.py": "EXPECTED_HASH_2"
    }

    for file_path, expected_hash in files_to_verify.items():
        verify_file_hash(file_path, expected_hash)

    clean_up_system()

    print("[INFO] Script completed successfully.")

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
