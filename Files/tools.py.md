# 🛠️ Cybersecurity Tools Installer

## **Features**
- Installs categorized cybersecurity tools:  
  Reconnaissance, OSINT, Web Security, Password Cracking, Exploitation, Post-Exploitation, Forensics, Reverse Engineering, etc.  
- Automatically logs all failed installs and errors to `install_errors.log`.  
- Provides a summary of any tools that failed to install at the end.

---
## **Categories Sorted by Purpose**
### 🧭 Reconnaissance
- [nmap](https://nmap.org) – Host discovery and port scanning.  
- [nikto](https://cirt.net/Nikto2) – Web server vulnerability scanner.  
- [metasploit-framework](https://www.metasploit.com) – Penetration testing framework.  
- [burpsuite](https://portswigger.net/burp) – Web proxy and vulnerability scanner.  
- [zaproxy](https://www.zaproxy.org) – Web application security scanner.  
- [theharvester](https://github.com/laramies/theHarvester) – OSINT for emails, domains, and IPs.  
- [recon-ng](https://github.com/lanmaster53/recon-ng) – OSINT automation framework.  
- [amass](https://github.com/OWASP/Amass) – Subdomain enumeration and mapping.  
- [whatweb](https://github.com/urbanadventurer/WhatWeb) – Web fingerprinting utility.  
- [masscan](https://github.com/robertdavidgraham/masscan) – Internet-scale port scanner.  
- [ffuf](https://github.com/ffuf/ffuf) – Fast web fuzzer for content discovery.  

### 🌐 Open Source Intelligence (OSINT)
- [sherlock](https://github.com/sherlock-project/sherlock) – Username search across social networks.  
- [metagoofil](https://github.com/laramies/metagoofil) – Metadata scraper from public documents.  
- [shodan](https://www.shodan.io) – Search engine for Internet-connected devices.  
- [dnsrecon](https://github.com/darkoperator/dnsrecon) – DNS records enumeration tool.  
- [dnsenum](https://github.com/fwaeytens/dnsenum) – Multithreaded DNS recon script.  

### 💻 Web Application Security
- [sqlmap](https://sqlmap.org) – Automated SQL injection and database takeover tool.  
- [xsstrike](https://github.com/s0md3v/XSStrike) – Advanced XSS detection suite.  
- [wapiti](https://github.com/wapiti-scanner/wapiti) – Web application vulnerability scanner.  
- [commix](https://github.com/commixproject/commix) – Command injection exploitation framework.  

### 🔐 Password Cracking
- [john](https://www.openwall.com/john/) – Versatile password cracker.  
- [hashcat](https://hashcat.net/hashcat/) – GPU-based password recovery tool.  
- [hydra](https://github.com/vanhauser-thc/thc-hydra) – Network login brute-force tool.  
- [pdfcrack](https://www.kali.org/tools/pdfcrack/) – PDF password recovery.  
- [steghide](https://www.kali.org/tools/steghide/) – Steganography tool for hiding/extracting data.  

### 🌐 Network Analysis
- [wireshark](https://www.wireshark.org) – GUI packet analyzer.  
- [tcpdump](https://www.tcpdump.org) – Command-line packet sniffer.  
- [ettercap](https://www.ettercap-project.org) – Network MITM attack tool.  
- [aircrack-ng](https://www.aircrack-ng.org) – WiFi auditing and cracking suite.  
- [bettercap](https://www.bettercap.org) – Advanced MITM and network attack framework.  
- [mitmproxy](https://mitmproxy.org) – Intercepting proxy for HTTP(S) traffic.  
- [responder](https://github.com/lgandx/Responder) – LLMNR, NBT-NS, and MDNS poisoner.  
- [ncat](https://nmap.org/ncat/) – Netcat replacement shipped with Nmap.  

### 🧠 Binary & Malware Analysis
- [radare2](https://rada.re/n/) – Reverse engineering framework.  
- [binwalk](https://github.com/ReFirmLabs/binwalk) – Firmware analysis toolkit.  
- [strings](https://man7.org/linux/man-pages/man1/strings.1.html) – Extract printable strings from binaries.  
- [yara](https://virustotal.github.io/yara/) – Pattern matching for malware identification.  
- [frida](https://frida.re/) – Dynamic instrumentation toolkit.  
- [ghidra](https://ghidra-sre.org/) – NSA’s software reverse engineering framework.  
- [gdb](https://www.gnu.org/software/gdb/) – GNU Debugger for reverse engineering and exploit development.  
- [hexedit](https://packages.debian.org/search?keywords=hexedit) – Hex editor for binary inspection.  

### ⚙️ Exploitation
- [exploitdb](https://www.exploit-db.com) – Public exploit archive.  
- [impacket-scripts](https://github.com/SecureAuthCorp/impacket) – Python tools for network protocols.  
- [empire](https://github.com/BC-SECURITY/Empire) – Post-exploitation and C2 framework.  
- [mimikatz](https://github.com/gentilkiwi/mimikatz) – Credential extraction from Windows systems.  
- [bloodhound](https://github.com/BloodHoundAD/BloodHound) – Active Directory enumeration and visualization.  
- [crackmapexec](https://github.com/byt3bl33d3r/CrackMapExec) – Network exploitation and lateral movement tool.  

### 🧰 Post-Exploitation & Forensics
- [volatility](https://www.volatilityfoundation.org) – Memory forensics framework.  
- [autopsy](https://www.sleuthkit.org/autopsy/) – Digital forensics toolkit.  
- [pwncat](https://github.com/calebstewart/pwncat) – Cross-platform post-exploitation tool.  
- [smbmap](https://github.com/ShawnDEvans/smbmap) – SMB share enumeration and access.  
- [foremost](https://github.com/awolfly/foremost) – File carving utility for forensic recovery.  
- [bulk_extractor](https://digitalcorpora.org/tools/bulk_extractor) – Forensic artifact extractor.  

### 🎭 Social Engineering
- [set](https://github.com/trustedsec/social-engineer-toolkit) – Social engineering attack platform.  
- [beef-xss](https://github.com/beefproject/beef) – Browser exploitation framework.  

### 📡 Wireless & IoT Security
- [wifite](https://github.com/derv82/wifite2) – Automated WiFi attacks and auditing.  
- [reaver](https://github.com/t6x/reaver-wps-fork-t6x) – WPS brute-force attack tool.  

### 🧾 Utility Tools
- [postman](https://www.postman.com) – API testing platform.  
- [netcat](https://nc110.sourceforge.io) – Networking utility.  
- [socat](http://www.dest-unreach.org/socat/) – Bidirectional data relay.  
- [gobuster](https://github.com/OJ/gobuster) – Directory and DNS brute-forcing tool.  
- [trivy](https://github.com/aquasecurity/trivy) – Container and dependency scanner.  
- [scoutsuite](https://github.com/nccgroup/ScoutSuite) – Multi-cloud auditing tool.  
- [rkhunter](https://rkhunter.sourceforge.net) – Rootkit detection scanner.  
- [chkrootkit](http://www.chkrootkit.org) – Local rootkit detection tool.  

### 💻 Development Utilities
- [python3](https://www.python.org) – Main scripting language.  
- [ruby](https://www.ruby-lang.org) – Exploit and automation scripting.  
- [golang](https://golang.org) – Compiled language for tooling.  
- [jq](https://stedolan.github.io/jq/) – JSON processor.  
- [tmux](https://github.com/tmux/tmux/wiki) – Terminal multiplexer.  
- [exiftool](https://exiftool.org) – Metadata extraction utility.  
---

# The Script
```python
#!/usr/bin/env python3
import subprocess
import hashlib
import os
import logging
import shutil
import sys
from datetime import datetime

logging.basicConfig(
    filename='install_errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def run_command(command, fatal=False):
    """Run a shell command safely."""
    print(f"Running: {command}")
    try:
        cp = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        if cp.stdout:
            print(cp.stdout.strip())
        return True
    except subprocess.CalledProcessError as e:
        logging.error("Command failed [%s]: %s\nSTDERR: %s", command, e.returncode, e.stderr)
        print(f"Command failed: {command}")
        if fatal:
            sys.exit(1)
        return False

def ensure_opt_dir():
    """Ensure /opt exists."""
    if not os.path.exists("/opt"):
        print("Creating /opt directory...")
        os.makedirs("/opt", exist_ok=True)
    else:
        print("/opt directory exists.")

def verify_packages_with_debsums():
    print("Verifying installed packages with debsums...")
    run_command("apt-get install -y debsums")
    result = subprocess.run("debsums -c", shell=True, text=True, capture_output=True)
    if result.returncode == 0 and not result.stdout.strip():
        print("All packages passed verification.")
    else:
        print("Some packages failed verification:")
        print(result.stdout.strip())
        logging.error("Debsums verification issues: %s", result.stdout.strip())

def clean_sources_list():
    print("Cleaning APT sources list...")
    src = "/etc/apt/sources.list"
    bak = "/etc/apt/sources.list.bak"
    try:
        if os.path.exists(src) and not os.path.exists(bak):
            shutil.copy2(src, bak)
        if not os.path.exists(bak):
            print("No sources.list found.")
            return
        with open(bak, "r") as s, open(src, "w") as d:
            for line in s:
                if "blacklisted-source.example.com" not in line:
                    d.write(line)
        run_command("apt-get update --fix-missing")
    except Exception as e:
        logging.error("Error cleaning sources.list: %s", str(e))

def verify_file_hash(path, expected):
    print(f"Verifying hash for {path}...")
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        actual = sha256.hexdigest()
        if actual == expected:
            print(f"{path} hash OK.")
        else:
            print(f"Hash mismatch for {path}")
            logging.error("Hash mismatch: %s expected=%s found=%s", path, expected, actual)
    except FileNotFoundError:
        print(f"File not found: {path}")
        logging.error("File not found: %s", path)
    except Exception as e:
        logging.error("Error verifying hash %s: %s", path, str(e))

def install_packages(packages):
    failed = []
    for pkg in packages:
        print(f"Installing: {pkg}")
        ok = run_command(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg}")
        if not ok:
            failed.append(pkg)
    return failed

# Manual installers for tools not in default repos
def install_burpsuite():
    print("Installing Burp Suite Community Edition manually...")
    burp_path = "/opt/BurpSuiteCommunity"
    burp_launcher = "/usr/local/bin/burpsuite"
    try:
        if not os.path.exists(burp_path):
            url = "https://portswigger.net/burp/releases/download?product=community&type=Linux"
            installer = "/tmp/burpsuite_installer.sh"
            run_command(f"wget --content-disposition -O {installer} '{url}'")
            run_command(f"chmod +x {installer}")
            run_command(f"{installer} -q -dir {burp_path}")
        if not os.path.exists(burp_launcher):
            with open(burp_launcher, "w") as f:
                f.write(f"#!/bin/bash\n{burp_path}/BurpSuiteCommunity &\n")
            os.chmod(burp_launcher, 0o755)
        print("Burp Suite installed successfully.")
        return True
    except Exception as e:
        logging.error("Burp Suite installation failed: %s", str(e))
        print("Burp Suite installation failed; logged.")
        return False

def install_reconng():
    print("Installing recon-ng manually...")
    try:
        run_command("git clone https://github.com/lanmaster53/recon-ng.git /opt/recon-ng")
        run_command("ln -sf /opt/recon-ng/recon-ng.py /usr/local/bin/recon-ng")
        run_command("pip install -r /opt/recon-ng/REQUIREMENTS")
        print("recon-ng installed successfully.")
        return True
    except Exception as e:
        logging.error("recon-ng install failed: %s", str(e))
        return False

def install_metagoofil():
    print("Installing metagoofil manually...")
    try:
        run_command("git clone https://github.com/laramies/metagoofil.git /opt/metagoofil")
        run_command("ln -sf /opt/metagoofil/metagoofil.py /usr/local/bin/metagoofil")
        print("metagoofil installed successfully.")
        return True
    except Exception as e:
        logging.error("metagoofil install failed: %s", str(e))
        return False

def install_empire():
    print("Installing Empire manually...")
    try:
        run_command("git clone https://github.com/BC-SECURITY/Empire.git /opt/Empire")
        run_command("cd /opt/Empire && DEBIAN_FRONTEND=noninteractive ./setup/install.sh")
        print("Empire installed successfully.")
        return True
    except Exception as e:
        logging.error("Empire install failed: %s", str(e))
        return False

def install_beef():
    print("Installing BeEF manually...")
    try:
        run_command("git clone https://github.com/beefproject/beef.git /opt/beef")
        run_command("cd /opt/beef && ./install")
        run_command("ln -sf /opt/beef/beef /usr/local/bin/beef-xss")
        print("BeEF installed successfully.")
        return True
    except Exception as e:
        logging.error("BeEF install failed: %s", str(e))
        return False

def install_ghidra():
    print("Installing Ghidra manually...")
    try:
        run_command("wget -O /tmp/ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/latest/download/ghidra.zip")
        run_command("unzip -o /tmp/ghidra.zip -d /opt/ghidra")
        run_command("ln -sf /opt/ghidra/*/ghidraRun /usr/local/bin/ghidra")
        print("Ghidra installed successfully.")
        return True
    except Exception as e:
        logging.error("Ghidra install failed: %s", str(e))
        return False

def install_postman():
    print("Installing Postman manually...")
    try:
        run_command("wget -O /tmp/postman.tar.gz https://dl.pstmn.io/download/latest/linux64")
        run_command("tar -xzf /tmp/postman.tar.gz -C /opt")
        run_command("ln -sf /opt/Postman/Postman /usr/local/bin/postman")
        print("Postman installed successfully.")
        return True
    except Exception as e:
        logging.error("Postman install failed: %s", str(e))
        return False

def install_impacket():
    print("Installing Impacket manually (pip fallback)...")
    try:
        run_command("pip install impacket")
        print("Impacket installed successfully via pip.")
        return True
    except Exception as e:
        logging.error("Impacket pip install failed: %s", str(e))
        return False

def clean_up_system():
    print("Cleaning system...")
    run_command("apt-get autoremove -y")
    run_command("apt-get clean")
    print("Cleanup complete.")

def refresh_keys():
    print("Refreshing system keys (if applicable)...")
    run_command("apt-get install --reinstall -y kali-archive-keyring", fatal=False)

def update_system():
    print("Updating system...")
    run_command("apt-get update --allow-releaseinfo-change")
    run_command("apt-get -y upgrade --fix-missing")

def configure_sysctl():
    print("Applying sysctl security hardening...")
    cfg = """# Security-focused sysctl settings
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
        conf = "/etc/sysctl.conf"
        with open(conf, "a+") as f:
            f.seek(0)
            if "# Security-focused sysctl settings" not in f.read():
                f.write("\n" + cfg)
        run_command("sysctl -p")
    except Exception as e:
        logging.error("Sysctl configuration failed: %s", str(e))

def setup_cron_job():
    print("Configuring daily Lynis scan...")
    entry = "0 3 * * * root /usr/sbin/lynis audit system"
    cron = "/etc/crontab"
    try:
        with open(cron, "a+") as f:
            f.seek(0)
            if entry not in f.read():
                f.write(entry + "\n")
    except Exception as e:
        logging.error("Cron setup failed: %s", str(e))

def main():
    if os.geteuid() != 0:
        print("Run as root.")
        sys.exit(1)

    os.environ["DEBIAN_FRONTEND"] = "noninteractive"
    failed_all = []

    print(f"=== Cybersecurity Tools Installer started {datetime.now()} ===")

    ensure_opt_dir()
    refresh_keys()
    update_system()
    clean_sources_list()

    essentials = ["wget", "curl", "git", "python3-pip", "gnupg", "software-properties-common", "ca-certificates", "lynis"]
    failed_all.extend(install_packages(essentials))

    tools = {
        "Reconnaissance": ["nmap", "nikto", "metasploit-framework", "zaproxy",
                           "theharvester", "amass", "whatweb", "masscan", "ffuf"],
        "OSINT": ["sherlock", "shodan", "dnsrecon", "dnsenum"],
        "WebAppSecurity": ["sqlmap", "xsstrike", "wapiti", "commix"],
        "PasswordCracking": ["john", "hashcat", "hydra", "pdfcrack", "steghide"],
        "NetworkAnalysis": ["wireshark", "tcpdump", "ettercap", "aircrack-ng", "bettercap",
                            "mitmproxy", "responder", "ncat"],
        "BinaryAnalysis": ["radare2", "binwalk", "strings", "yara", "frida", "gdb", "hexedit"],
        "Exploitation": ["exploitdb", "mimikatz", "bloodhound", "crackmapexec"],
        "PostExploitation": ["volatility", "autopsy", "pwncat", "smbmap", "foremost", "bulk-extractor"],
        "SocialEngineering": ["set"],
        "WirelessIoT": ["wifite", "reaver"],
        "Utilities": ["netcat", "socat", "gobuster", "trivy", "scoutsuite", "rkhunter", "chkrootkit"],
        "Development": ["python3", "ruby", "golang", "jq", "tmux", "exiftool"]
    }

    for cat, pkgs in tools.items():
        print(f"\nInstalling {cat} tools...")
        failed = install_packages(pkgs)
        if failed:
            failed_all.extend(failed)

    # Manual installers for non-repo tools
    manual_tools = {
        "burpsuite": install_burpsuite,
        "recon-ng": install_reconng,
        "metagoofil": install_metagoofil,
        "empire": install_empire,
        "beef-xss": install_beef,
        "ghidra": install_ghidra,
        "postman": install_postman,
        "impacket": install_impacket
    }

    for name, func in manual_tools.items():
        print(f"\nInstalling {name} manually...")
        if not func():
            failed_all.append(name)

    configure_sysctl()
    setup_cron_job()
    verify_packages_with_debsums()
    clean_up_system()

    if failed_all:
        print("\nSummary: installation/verification failures:")
        for i in sorted(set(failed_all)):
            print(f"  - {i}")
        logging.error("Failures: %s", ", ".join(sorted(set(failed_all))))
    else:
        print("\nAll tools installed and verified successfully.")

    print(f"=== Completed {datetime.now()} ===")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)
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
