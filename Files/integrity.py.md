# 🛡️ OS Hardening & Integrity Script

## **Features**
### 1. **System Preparation**
- Updates and upgrades all system packages.  
- Cleans unwanted or blacklisted APT sources.  
- Installs essential CLI tools (e.g., `wget`, `curl`, `gnupg`, `software-properties-common`).  

### 2. **System Hardening**
- Configures kernel and network-level hardening through secure `sysctl` parameters.  
- Sets up and enables:
  - **Fail2Ban** — protects SSH from brute-force attacks.  
  - **UFW (Uncomplicated Firewall)** — enforces inbound/outbound traffic control.  
  - **Auditd** — logs and monitors system activity.  
  - **Unattended Upgrades** — automatically installs security updates.  
- Disables root SSH login and enforces secure file permissions.  

### 3. **Integrity & Verification**
- Installs and runs **debsums** to verify system package integrity.  
- Supports SHA256 verification for critical binaries (e.g., `nmap`, `sqlmap`).  
- Performs automated cleanup (`autoremove`, `apt clean`).  

### 4. **Automated Auditing**
- Adds daily **Lynis** and **Rootkit Hunter** cron jobs for ongoing security auditing.  
- Logs all operations and errors to `system_hardening.log`.
---
# The Script
```python
#!/usr/bin/env python3
import subprocess
import hashlib
import os
import logging
import shutil

# === CONFIG ===
LOG_FILE = "system_hardening.log"
APT_TIMEOUT = 600
logging.basicConfig(filename=LOG_FILE, level=logging.ERROR,
                    format="%(asctime)s - %(levelname)s - %(message)s")


# === HELPER ===
def run_command(cmd: str, exit_on_fail=True) -> bool:
    """Run a shell command safely, log on failure."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    try:
        print(f"Running: {cmd}")
        subprocess.run(cmd, shell=True, check=True, timeout=APT_TIMEOUT, env=env)
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"Command failed: {cmd}\n{e}")
        if exit_on_fail:
            exit(1)
        return False
    except subprocess.TimeoutExpired as e:
        logging.error(f"Timeout: {cmd}\n{e}")
        return False


# === CORE FUNCTIONS ===
def refresh_kali_keys():
    print("Refreshing Kali archive keys...")
    run_command("wget -q -O - https://archive.kali.org/archive-key.asc | gpg --dearmor > /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg", exit_on_fail=False)


def update_system():
    print("Updating and upgrading system...")
    run_command("apt-get update --allow-releaseinfo-change", exit_on_fail=False)
    run_command("apt-get full-upgrade -y", exit_on_fail=False)


def clean_sources_list():
    print("Cleaning /etc/apt/sources.list...")
    try:
        orig = "/etc/apt/sources.list"
        backup = "/etc/apt/sources.list.bak"
        if os.path.exists(orig):
            os.replace(orig, backup)
            print(f"[INFO] Backup saved as {backup}")
            with open(backup, "r") as fin, open(orig, "w") as fout:
                for line in fin:
                    if "blacklisted-source.example.com" in line:
                        print(f"[REMOVED] {line.strip()}")
                    else:
                        fout.write(line)
            run_command("apt-get update --fix-missing", exit_on_fail=False)
        else:
            print("[WARN] /etc/apt/sources.list not found.")
    except Exception as e:
        logging.error(f"Failed to clean sources.list: {e}")


def configure_sysctl():
    print("Configuring sysctl hardening...")
    sysctl_conf = """
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
    path = "/etc/sysctl.conf"
    marker = "# Security-focused sysctl settings"
    try:
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(sysctl_conf)
            print(f"[INFO] Created {path}.")
        else:
            with open(path, "r+") as f:
                content = f.read()
                if marker not in content:
                    f.write("\n" + sysctl_conf)
                    print("[INFO] Appended sysctl hardening settings.")
        run_command("sysctl -p", exit_on_fail=False)
    except Exception as e:
        logging.error(f"Failed to configure sysctl: {e}")


def verify_packages_with_debsums():
    print("Verifying installed packages with debsums...")
    if shutil.which("debsums") is None:
        run_command("apt-get install -y debsums", exit_on_fail=False)
    result = subprocess.run("debsums -c", shell=True, text=True, capture_output=True)
    if result.returncode == 0:
        print("[INFO] All packages verified.")
    else:
        print("[WARNING] Some packages failed verification:")
        print(result.stdout.strip())


def verify_file_hash(path: str, expected_hash: str):
    print(f"Verifying {path}...")
    try:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        found = sha256.hexdigest()
        if found == expected_hash:
            print(f"[PASS] {path}")
        else:
            print(f"[FAIL] {path} hash mismatch!\nExpected: {expected_hash}\nFound:    {found}")
    except FileNotFoundError:
        logging.error(f"File not found: {path}")
    except Exception as e:
        logging.error(f"Hash verification failed for {path}: {e}")


def setup_cron_jobs():
    print("Setting up security cron jobs...")
    cron_entries = {
        "lynis": "0 3 * * * /usr/sbin/lynis audit system",
        "rkhunter": "0 2 * * * /usr/bin/rkhunter --update && /usr/bin/rkhunter --check --quiet"
    }
    path = "/etc/crontab"
    try:
        with open(path, "a+") as f:
            f.seek(0)
            content = f.read()
            for name, entry in cron_entries.items():
                if entry not in content:
                    f.write(entry + "\n")
                    print(f"[INFO] Added cron job: {name}")
                else:
                    print(f"[INFO] Cron job for {name} already exists.")
    except Exception as e:
        logging.error(f"Failed to setup cron jobs: {e}")


def install_security_tools():
    print("Installing security utilities...")
    packages = [
        "unattended-upgrades", "apt-listchanges",
        "fail2ban", "ufw", "auditd", "audispd-plugins", "debsums"
    ]
    for pkg in packages:
        run_command(f"apt-get install -y {pkg}", exit_on_fail=False)

    # Configure firewall
    run_command("ufw default deny incoming", exit_on_fail=False)
    run_command("ufw default allow outgoing", exit_on_fail=False)
    run_command("ufw allow ssh", exit_on_fail=False)
    run_command("ufw --force enable", exit_on_fail=False)

    # Harden SSH
    run_command("sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config", exit_on_fail=False)
    run_command("systemctl restart ssh", exit_on_fail=False)

    # Enable services
    run_command("systemctl enable fail2ban --now", exit_on_fail=False)
    run_command("systemctl enable auditd --now", exit_on_fail=False)

    # Enable unattended upgrades
    run_command("dpkg-reconfigure --priority=low unattended-upgrades", exit_on_fail=False)


def set_permissions():
    print("Setting secure file permissions...")
    run_command("chmod 640 /etc/shadow", exit_on_fail=False)
    run_command("chmod 644 /etc/passwd", exit_on_fail=False)


def clean_up_system():
    print("Cleaning up...")
    run_command("apt-get autoremove -y", exit_on_fail=False)
    run_command("apt-get clean", exit_on_fail=False)
    print("[INFO] Cleanup complete.")


# === MAIN ===
def main():
    if os.geteuid() != 0:
        raise SystemExit("This script must be run as root. Use sudo.")

    refresh_kali_keys()
    update_system()
    clean_sources_list()
    configure_sysctl()
    install_security_tools()
    setup_cron_jobs()
    verify_packages_with_debsums()
    set_permissions()

    files_to_verify = {
        "/usr/bin/nmap": "EXPECTED_HASH_1",
        "/usr/share/sqlmap/sqlmap.py": "EXPECTED_HASH_2"
    }
    for path, expected_hash in files_to_verify.items():
        verify_file_hash(path, expected_hash)

    clean_up_system()
    print("[INFO] OS Hardening completed successfully.")


if __name__ == "__main__":
    main()
```
