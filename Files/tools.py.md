# Python Code to Install Cybersecurity Tools on Kali Linux
## This code will auto upgrade, auto update, and auto fix everything prior to installing a list of tools needed for cybersecurity work
---
## **Features**

### 1. **System Preparation**
- Automatically updates, upgrades, and fixes the system before installing tools.
- Cleans untrusted sources from `/etc/apt/sources.list` to maintain repository integrity.
- Installs basic utilities: `wget`, `curl`, `gnupg`, and `software-properties-common` for essential system functionality.

### 2. **System Configuration**
- Updates `/etc/sysctl.conf` with security-focused settings:
  - Disables IP redirects.
  - Enables logging of martian packets (suspicious packets from outside the subnet).
  - Restricts kernel access to reduce attack surface.

### 3. **Integrity Verification**
- Uses `debsums` to validate the integrity of installed packages.
- Verifies critical files against their expected SHA256 hashes.

### 4. **Automation**
- Schedules daily system audits using `Lynis` at 3:00 AM to identify system vulnerabilities.

### 5. **System Cleanup**
- Automatically removes unnecessary packages and cleans the system after installation.
- Logs errors and skips installation failures, providing a summary at the end.

## **Categorized Tool Installation**: Installs cybersecurity tools grouped by purpose:
#### Reconnaissance
- [nmap](https://nmap.org) - Network mapper for discovering hosts and services.
- [nikto](https://cirt.net/Nikto2) - Web server scanner for detecting vulnerabilities.
- [metasploit-framework](https://www.metasploit.com) - Comprehensive penetration testing framework.
- [burpsuite](https://portswigger.net/burp) - Web vulnerability scanner and proxy.
- [zaproxy](https://www.zaproxy.org) - Web application security testing tool.
- [theharvester](https://github.com/laramies/theHarvester) - Email, subdomain, and port scanner.
- [recon-ng](https://github.com/lanmaster53/recon-ng) - Reconnaissance framework with OSINT modules.
- [amass](https://github.com/OWASP/Amass) - Subdomain enumeration and network mapping.
- [whatweb](https://github.com/urbanadventurer/WhatWeb) - Web technology fingerprinting tool.
#### Open Source Intelligence (OSINT)
- [sherlock](https://github.com/sherlock-project/sherlock) - Social media username lookup.
- [metagoofil](https://github.com/laramies/metagoofil) - Metadata extraction tool for public documents.
- [shodan](https://www.shodan.io) - Search engine for internet-connected devices.
- [dnsrecon](https://github.com/darkoperator/dnsrecon) - DNS enumeration and record analysis.
- [dnsenum](https://github.com/fwaeytens/dnsenum) - Multithreaded DNS enumeration tool.
#### Web Application Security
- [sqlmap](https://sqlmap.org) - Automated SQL injection and database takeover tool.
- [xsstrike](https://github.com/s0md3v/XSStrike) - Advanced XSS detection and exploitation tool.
- [wapiti](https://github.com/wapiti-scanner/wapiti) - Web vulnerability scanner with multiple modules.
- [commix](https://github.com/commixproject/commix) - Automated command injection and exploitation tool.
#### Password and Authentication Cracking
- [john](https://www.openwall.com/john/) - Versatile password cracking tool.
- [hashcat](https://hashcat.net/hashcat/) - High-performance password recovery tool.
- [hydra](https://github.com/vanhauser-thc/thc-hydra) - Fast and flexible password brute-forcer.
- [pdfcrack](https://www.kali.org/tools/pdfcrack/) - Recover passwords and content from PDF-files
- [steghide](https://www.kali.org/tools/steghide/) - hide data in various kinds of image and audio files
#### Network Analysis and Traffic Monitoring
- [wireshark](https://www.wireshark.org) - Network protocol analyzer and packet sniffer.
- [tcpdump](https://www.tcpdump.org) - Lightweight command-line packet analyzer.
- [ettercap](https://www.ettercap-project.org) - Network traffic interception and manipulation tool.
- [aircrack-ng](https://www.aircrack-ng.org) - Wireless network cracking and monitoring suite.
#### Binary and Malware Analysis
- [radare2](https://rada.re/n/) - Advanced reverse engineering framework.
- [binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware analysis and extraction tool.
- [yara](https://virustotal.github.io/yara/) - Malware identification and classification tool.
- [strings](https://man7.org/linux/man-pages/man1/strings.1.html) - Extract human-readable strings from binary files.
- [ghidra](https://ghidra-sre.org/) - Free software reverse engineering (SRE) framework developed by the National Security Agency (NSA) of the United States
#### Exploitation Frameworks and Tools
- [exploitdb](https://www.exploit-db.com) - Public exploit repository.
- [impacket-scripts](https://github.com/SecureAuthCorp/impacket) - Tools for network protocols and exploitation.
- [empire](https://github.com/BC-SECURITY/Empire) - Post-exploitation and command-and-control framework.
- [mimikatz](https://github.com/gentilkiwi/mimikatz) - Credential extraction and manipulation tool.
- [bloodhound](https://github.com/BloodHoundAD/BloodHound) - Active Directory reconnaissance and exploitation tool.
#### Post-Exploitation and Digital Forensics
- [volatility](https://www.volatilityfoundation.org) - Memory forensics and analysis framework.
- [autopsy](https://www.sleuthkit.org/autopsy/) - Digital forensics and investigation tool.
#### Social Engineering
- [set](https://github.com/trustedsec/social-engineer-toolkit) - Comprehensive social engineering toolkit.
- [beef-xss](https://github.com/beefproject/beef) - Browser exploitation and XSS testing framework.
#### Wireless and IoT Security
- [wifite](https://github.com/derv82/wifite2) - Automated wireless network attacks.
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x) - WPA/WPS brute-forcing tool.
- [aircrack-ng](https://www.aircrack-ng.org) - Wireless network security auditing tool.
#### Utility and Maintenance Tools
- [postman](https://www.postman.com) - API testing and collaboration platform.
- [netcat](https://nc110.sourceforge.io) - Networking utility for debugging and data transfer.
- [socat](http://www.dest-unreach.org/socat/) - Multipurpose data transfer tool.
- [gobuster](https://github.com/OJ/gobuster) - Directory, DNS, and file brute-forcing tool.
- [trivy](https://github.com/aquasecurity/trivy) - Container vulnerability and misconfiguration scanner.
- [scoutsuite](https://github.com/nccgroup/ScoutSuite) - Cloud environment security auditing tool.
- [rkhunter](https://rkhunter.sourceforge.net) - Rootkit detection and system auditing tool.
- [chkrootkit](http://www.chkrootkit.org) - Local rootkit detection tool.
#### Development Utilities
- [python3](https://www.python.org) - High-level programming language.
- [ruby](https://www.ruby-lang.org) - Dynamic programming language.
- [golang](https://golang.org) - Statically typed programming language.
- [jq](https://stedolan.github.io/jq/) - Lightweight JSON processor.
- [tmux](https://github.com/tmux/tmux/wiki) - Terminal multiplexer for session management.
- [exiftool](https://exiftool.org) - Metadata extraction and analysis tool.

# The Script
```py
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
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Command failed: {command}\n{e}")
        if exit_on_fail:
            exit(1)

# Function to verify package integrity using debsums
def verify_packages_with_debsums():
    print("Verifying installed packages with debsums...")
    run_command("apt install -y debsums")
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
        run_command("apt-get update", exit_on_fail=False)
    except Exception as e:
        logging.error(f"[ERROR] Failed to clean sources list: {e}")
        exit(1)

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
            run_command(f"apt install -y {package}", exit_on_fail=False)
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
    run_command("apt autoremove -y")
    run_command("apt clean")
    print("[INFO] Cleanup completed.")

# Update and upgrade system
def update_system():
    print("Updating and upgrading the system...")
    run_command("apt update && apt upgrade -y")

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
        with open("/etc/sysctl.conf", "a") as sysctl_file:
            sysctl_file.write(sysctl_config)
        run_command("sysctl -p")
    except Exception as e:
        logging.error(f"[ERROR] Failed to configure sysctl: {e}")

# Set up a cron job for Lynis
def setup_cron_job():
    try:
        run_command('echo "0 3 * * * /usr/sbin/lynis audit system" | tee -a /etc/crontab')
    except Exception as e:
        logging.error(f"[ERROR] Failed to set up cron job: {e}")

# Main function to orchestrate tasks
def main():
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
        "/usr/bin/sqlmap": "EXPECTED_HASH_2"
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
