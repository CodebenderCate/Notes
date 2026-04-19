# **Features**

## 1. **System Preparation**
* **Updates & Upgrades**: Synchronizes local package indexes and performs a full system upgrade.
* **APT Source Hardening**: Validates `/etc/apt/sources.list` to ensure communication only with official Kali mirrors.
* **Core Essentials**: Installs utilities like `wget`, `curl`, `htop`, and `vim`, along with the OpenJDK environment for Ghidra.
* **Dependency Management**: Deploys [apt-file](https://pkg-os.alioth.debian.org/apt-file.html) to locate missing shared libraries in the flat environment.

## 2. **System & Network Hardening**
* **Kernel Security**: Hardens the kernel via `sysctl` to restrict `dmesg`, prevent IP spoofing, and protect symlinks.
* **Network Stealth**: Configures [UFW](https://launchpad.net/ufw) to "default deny" incoming traffic, making the VM invisible to target scans.
* **Audit Automation**: Sets up daily [Lynis](https://cisofy.com/lynis/) audits to monitor system compliance.

## 3. **Integrity Checking**
* **Package Verification**: Uses [debsums](https://manpages.debian.org/stretch/debsums/debsums.1.en.html) for high-speed validation of installed packages.
* **Binary Authenticity**: Alerts only if critical binaries have been modified, ensuring a trustworthy environment.

## 4. **Modern Forensics & Tool Utility**
* **Volatility 3 Framework**: Installs the standard for memory forensics from source for latest plugin support.
* **Metasploit Optimization**: Initializes the [msfdb](https://www.metasploit.com) for near-instant exploit searches.
* **Wordlist Readiness**: Decompresses the industry-standard `rockyou.txt` wordlist for immediate use.

## 5. **Automated Setup & Logging**
* **Flat Installation**: Installs a full offensive suite directly to the system without container overhead.
* **Audit Trail**: Redirects all failures to a persistent errors.log for easy troubleshooting.
* **Storage Optimization**: Automatically invokes autoremove to purge orphaned dependencies and clean to clear the local repository of retrieved package files.

---

# **Categorized Tool Installation**

## Reconnaissance & OSINT
* [nmap](https://nmap.org) - Host discovery and advanced port scanning.
* [nikto](https://cirt.net/Nikto2) – Web server vulnerability scanner.
* [theharvester](https://github.com/laramies/theHarvester) – OSINT for emails, domains, and IPs.
* [recon-ng](https://github.com/lanmaster53/recon-ng) – OSINT automation framework.
* [amass](https://github.com/OWASP/Amass) – Subdomain enumeration.
* [sherlock](https://github.com/sherlock-project/sherlock) – Username search across social networks.
* [shodan](https://www.shodan.io) – Search engine for connected devices.
* [gobuster](https://github.com/OJ/gobuster) – High-speed directory and DNS brute-forcing.

## Web Application Security
* [sqlmap](https://sqlmap.org) – Automated SQL injection tool.
* [xsstrike](https://github.com/s0md3v/XSStrike) – Advanced XSS detection.
* [burpsuite](https://portswigger.net/burp) – Web proxy and scanner.
* [zaproxy](https://www.zaproxy.org) – Web app security scanner.

## Password & Authentication Cracking
* [john](https://www.openwall.com/john/) – Versatile password cracker.
* [hashcat](https://hashcat.net/hashcat/) – High-performance password recovery.
* [hydra](https://github.com/vanhauser-thc/thc-hydra) – Login brute-force tool.
* [steghide](https://www.kali.org/tools/steghide/) – Steganography tool.

## Network & Wireless Analysis
* [wireshark](https://www.wireshark.org) – Graphical protocol analyzer.
* [tcpdump](https://www.tcpdump.org) – CLI-based packet sniffer.
* [ettercap](https://www.ettercap-project.org) – Network MITM tool.
* [aircrack-ng](https://www.aircrack-ng.org) – WiFi auditing suite.
* [responder](https://github.com/lgandx/Responder) – LLMNR, NBT-NS, and MDNS poisoner.

## Binary, Malware & Forensic Analysis
* [ghidra](https://ghidra-sre.org/) – NSA’s SRE framework (Java-optimized).
* [radare2](https://rada.re/n/) – Reverse engineering framework.
* [binwalk](https://github.com/ReFirmLabs/binwalk) – Firmware analyzer.
* [yara](https://virustotal.github.io/yara/) – Pattern matching for malware.
* [volatility3](https://www.volatilityfoundation.org) – Modern memory forensics.
* [autopsy](https://www.sleuthkit.org/autopsy/) – Digital forensics platform.

## Exploitation & Post-Exploitation
* [metasploit-framework](https://www.metasploit.com) – Database-optimized exploitation suite.
* [set](https://github.com/trustedsec/social-engineer-toolkit) – Social engineering attacks.
* [exploitdb](https://www.exploit-db.com) – Local exploit archive.
* [impacket-scripts](https://github.com/fortra/impacket) – Collection of Python network tools.

## Utility & Maintenance
* [exiftool](https://exiftool.org) – Metadata extractor.
* [jq](https://stedolan.github.io/jq/) – JSON processor.
* [tmux](https://github.com/tmux/tmux/wiki) – Terminal multiplexer.
---
# The Script
```py
import subprocess
import os
import logging
import shutil
import re

# LOGGING: Audits every action and records errors locally.
logging.basicConfig(filename='errors.log', level=logging.ERROR, format='%(asctime)s - %(message)s')

def run_command(command, exit_on_fail=True):
    """Executes shell commands directly on the host."""
    try:
        print(f"[*] Running: {command}")
        subprocess.run(command, shell=True, check=True)
    except subprocess.CalledProcessError as e:
        logging.error(f"[ERROR] Command failed: {command}\n{e}")
        if exit_on_fail:
            exit(1)

def configure_sysctl():
    """Hardens the kernel. Checks for existing lines to prevent duplicates."""
    print("\n[*] Auditing sysctl hardening...")
    settings = {
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.log_martians": "1",
        "fs.protected_symlinks": "1",
        "fs.protected_hardlinks": "1",
        "kernel.dmesg_restrict": "1",
        "kernel.kptr_restrict": "2"
    }
    try:
        existing_cleaned = set()
        if os.path.exists("/etc/sysctl.conf"):
            with open("/etc/sysctl.conf", "r") as f:
                existing_cleaned = {re.sub(r'\s+', '', l) for l in f if '=' in l}
        
        to_add = [f"{k} = {v}" for k, v in settings.items() if f"{k}={v}" not in existing_cleaned]
        
        if to_add:
            with open("/etc/sysctl.conf", "a") as f:
                f.write("\n# Security Hardening - Automated\n")
                for entry in to_add:
                    f.write(f"{entry}\n")
            run_command("sysctl -p")
            print(f"  [+] Applied {len(to_add)} new settings.")
    except Exception as e:
        logging.error(f"Sysctl error: {e}")

def setup_firewall():
    """Configures UFW for a stealthy network posture."""
    print("\n[*] Hardening network with UFW (Stealth Mode)...")
    run_command("apt install -y ufw")
    run_command("ufw default deny incoming")
    run_command("ufw default allow outgoing")
    run_command("ufw --force enable")

def finalize_utility():
    """Optimizes tool performance and prepares data."""
    print("\n[*] Finalizing tool utility...")
    run_command("msfdb init", exit_on_fail=False)
    
    wordlist_gz = "/usr/share/wordlists/rockyou.txt.gz"
    wordlist_txt = "/usr/share/wordlists/rockyou.txt"
    if os.path.exists(wordlist_gz) and not os.path.exists(wordlist_txt):
        run_command(f"gunzip {wordlist_gz}")
    
    run_command("apt-file update", exit_on_fail=False)

def install_volatility3():
    """Installs Volatility 3 globally into /opt."""
    print("\n[*] Installing Volatility 3...")
    target_dir = "/opt/volatility3"
    run_command("apt install -y python3-pip python3-setuptools git libpcre3-dev libarchive-dev")

    if not os.path.exists(target_dir):
        run_command(f"git clone https://github.com/volatilityfoundation/volatility3.git {target_dir}")
    else:
        run_command(f"cd {target_dir} && git pull")

    run_command(f"ln -sf {target_dir}/vol.py /usr/local/bin/vol3")

def cleanup_system():
    """Removes junk, clears apt cache, and purges orphaned dependencies."""
    print("\n[*] Purging unnecessary packages and clearing cache...")
    # autoremove -y: deletes packages that were auto-installed to satisfy dependencies for other packages and are now no longer needed.
    run_command("apt autoremove -y")
    # clean: clears out the local repository of retrieved package files (.deb files).
    run_command("apt clean")
    # purge: removes configuration files for uninstalled packages
    run_command("apt autoclean")

def main():
    if os.geteuid() != 0:
        exit("Error: Run as root (sudo).")

    # 1. System Maintenance
    run_command("apt update && apt upgrade -y")
    
    # 2. Bulk Tool Install
    essential = ["wget", "curl", "debsums", "lynis", "openjdk-17-jdk", "apt-file", "htop", "vim"]
    tools = ["nmap", "sqlmap", "wireshark", "metasploit-framework", "hashcat", "john", "ghidra"]
    utility = ["responder", "sherlock", "social-engineer-toolkit", "gobuster", "exiftool"]
    
    all_packages = essential + tools + utility
    run_command(f"apt install -y {' '.join(all_packages)}", exit_on_fail=False)
    
    # 3. Hardening and Setup
    install_volatility3()
    configure_sysctl()
    setup_firewall()
    finalize_utility()
    
    # 4. Integrity Check
    print("\n[*] Verifying binary integrity...")
    run_command("debsums -sc 2>/dev/null", exit_on_fail=False)

    # 5. The Cleanup
    cleanup_system()
    
    print("\n[COMPLETE] VM is hardened, optimized, and scrubbed clean.")

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
