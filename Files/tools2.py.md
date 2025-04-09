import subprocess
import hashlib
import os
import logging
import requests
import json

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

# Install Ollama and Mistral
def install_mistral_ollama():
    print("[INFO] Installing Ollama and Mistral model for local AI analysis...")
    run_command("curl -fsSL https://ollama.com/install.sh | sh")
    run_command("ollama run mistral")  # Pulls and runs the model

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

    install_mistral_ollama()  # Install local AI for Ghidra

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