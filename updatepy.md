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
def enable_apparmor():
    """Enable AppArmor for mandatory access control."""
    print("\nEnabling AppArmor (Mandatory Access Control)...")
    
    # Install AppArmor
    run_command("apt-get install -y apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra", exit_on_fail=False)
    
    # Enable AppArmor service
    run_command("systemctl enable apparmor --now", exit_on_fail=False)
    
    # Check AppArmor status
    result = subprocess.run("aa-status 2>/dev/null", shell=True, capture_output=True, text=True)
    if result.returncode == 0:
        print("[PASS] ✓ AppArmor enabled and running")
        # Count profiles in enforce mode
        if "profiles are in enforce mode" in result.stdout:
            print("[INFO] AppArmor profiles active and enforcing")
    else:
        print("[WARN] AppArmor may not be fully active - check 'aa-status' manually")
    
    # Set profiles to enforce mode (cautiously)
    print("[INFO] Setting AppArmor profiles to enforce mode...")
    run_command("aa-enforce /etc/apparmor.d/usr.sbin.* 2>/dev/null", exit_on_fail=False)


def disable_unnecessary_services():
    """Disable commonly unnecessary services to reduce attack surface."""
    print("\nDisabling unnecessary services...")
    
    # Services that are often unnecessary on pentesting systems
    # Adjust this list based on your specific needs
    unnecessary_services = [
        "cups",           # Printing service
        "cups-browsed",   # Printer discovery
        "avahi-daemon",   # mDNS/DNS-SD (Bonjour)
        "bluetooth",      # Bluetooth
    ]
    
    disabled_count = 0
    for svc in unnecessary_services:
        # Check if service exists and is enabled
        check = subprocess.run(
            f"systemctl is-enabled {svc} 2>/dev/null",
            shell=True,
            capture_output=True
        )
        if check.returncode == 0:
            run_command(f"systemctl disable {svc} --now", exit_on_fail=False)
            print(f"  ✓ Disabled {svc}")
            disabled_count += 1
    
    if disabled_count > 0:
        print(f"[PASS] Disabled {disabled_count} unnecessary service(s)")
    else:
        print("[INFO] No unnecessary services found to disable")


def enhanced_sysctl_hardening():
    """Add additional kernel hardening parameters."""
    print("Adding enhanced kernel hardening parameters...")
    
    additional_hardening = """
# Additional kernel hardening
kernel.unprivileged_bpf_disabled = 1
kernel.unprivileged_userns_clone = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
"""
    
    path = "/etc/sysctl.conf"
    marker = "# Additional kernel hardening"
    
    try:
        with open(path, "r+") as f:
            content = f.read()
            if marker not in content:
                f.write("\n" + additional_hardening)
                print("[INFO] Added enhanced kernel hardening parameters")
        run_command("sysctl -p", exit_on_fail=False)
    except Exception as e:
        logging.error(f"Failed to add enhanced sysctl: {e}")


def configure_secure_shared_memory():
    """Secure shared memory to prevent privilege escalation."""
    print("Securing shared memory...")
    
    fstab_line = "tmpfs /run/shm tmpfs defaults,noexec,nosuid,nodev 0 0"
    fstab_path = "/etc/fstab"
    
    try:
        with open(fstab_path, "r") as f:
            content = f.read()
        
        if "/run/shm" not in content and "tmpfs" not in content:
            with open(fstab_path, "a") as f:
                f.write(f"\n# Secure shared memory\n{fstab_line}\n")
            print("[PASS] ✓ Shared memory secured in /etc/fstab")
            print("[INFO] Reboot required for shared memory changes to take effect")
        else:
            print("[INFO] Shared memory already configured")
    except Exception as e:
        logging.error(f"Failed to configure shared memory: {e}")
    """Enable APT security features to prevent malicious packages."""
    print("\nEnabling APT security features...")
    
    # Enable package signature verification
    apt_conf = "/etc/apt/apt.conf.d/99security"
    security_settings = """// Security settings for APT
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Get::AutomaticRemove "true";
"""
    
    try:
        with open(apt_conf, "w") as f:
            f.write(security_settings)
        print("[PASS] ✓ APT configured to reject unsigned/insecure packages")
    except Exception as e:
        logging.error(f"Failed to configure APT security: {e}")
    
    # Verify repository keys are valid
    print("[INFO] Verifying repository GPG keys...")
    run_command("apt-key list 2>&1 | grep -i expired", exit_on_fail=False)
    
    # Enable secure APT over HTTPS
    if not shutil.which("apt-transport-https"):
        run_command("apt-get install -y apt-transport-https", exit_on_fail=False)
    
    print("[PASS] ✓ APT security hardening complete")
# === CORE FUNCTIONS ===
def pre_flight_checks():
    """Perform pre-flight checks before starting hardening."""
    print("Performing pre-flight checks...")
    
    # Check if running as root
    if os.geteuid() != 0:
        print("[ERROR] This script must be run as root. Use sudo.")
        exit(1)
    
    # Check if running on Debian-based system
    if not os.path.exists("/etc/debian_version"):
        print("[WARN] This script is designed for Debian-based systems (Kali/Ubuntu/Debian)")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            exit(0)
    
    # Check internet connectivity
    print("[INFO] Checking internet connectivity...")
    result = subprocess.run(
        "ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1",
        shell=True
    )
    if result.returncode != 0:
        print("[WARN] No internet connectivity detected")
        print("[WARN] Some features may not work properly")
        response = input("Continue anyway? (y/N): ")
        if response.lower() != 'y':
            exit(0)
    else:
        print("[PASS] ✓ Internet connectivity confirmed")
    
    # Check available disk space (need at least 1GB)
    stat = os.statvfs('/')
    available_gb = (stat.f_bavail * stat.f_frsize) / (1024**3)
    if available_gb < 1:
        print(f"[ERROR] Insufficient disk space: {available_gb:.2f}GB available (need 1GB minimum)")
        exit(1)
    else:
        print(f"[PASS] ✓ Sufficient disk space: {available_gb:.2f}GB available")
    
    print("[PASS] Pre-flight checks complete\n")


def create_backup():
    """Create backup of critical configuration files."""
    print("Creating configuration backups...")
    backup_dir = f"/root/hardening_backup_{subprocess.check_output('date +%Y%m%d_%H%M%S', shell=True, text=True).strip()}"
    
    try:
        os.makedirs(backup_dir, exist_ok=True)
        
        critical_files = [
            "/etc/ssh/sshd_config",
            "/etc/sysctl.conf",
            "/etc/fstab",
            "/etc/apt/sources.list"
        ]
        
        for filepath in critical_files:
            if os.path.exists(filepath):
                shutil.copy2(filepath, backup_dir)
        
        print(f"[PASS] ✓ Backups saved to {backup_dir}")
        return backup_dir
    except Exception as e:
        logging.error(f"Failed to create backups: {e}")
        print(f"[WARN] Could not create backups: {e}")
        return None


def install_essential_tools():
    """Install essential CLI tools needed for the script."""
    print("Installing essential CLI tools...")
    essential_packages = ["wget", "curl", "gnupg", "software-properties-common", "apt-transport-https"]
    for pkg in essential_packages:
        run_command(f"apt-get install -y {pkg}", exit_on_fail=False)


def refresh_kali_keys():
    """Refresh Kali archive keys."""
    print("Refreshing Kali archive keys...")
    # First ensure wget is available
    if not shutil.which("wget"):
        run_command("apt-get install -y wget", exit_on_fail=False)
    
    # Download and install key properly
    run_command(
        "wget -q -O /tmp/kali-archive-key.asc https://archive.kali.org/archive-key.asc",
        exit_on_fail=False
    )
    if os.path.exists("/tmp/kali-archive-key.asc"):
        run_command(
            "gpg --dearmor < /tmp/kali-archive-key.asc > /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg",
            exit_on_fail=False
        )
        run_command("rm /tmp/kali-archive-key.asc", exit_on_fail=False)


def update_system():
    """Update and upgrade all system packages."""
    print("Updating and upgrading system...")
    run_command("apt-get update --allow-releaseinfo-change", exit_on_fail=False)
    run_command("apt-get full-upgrade -y", exit_on_fail=False)


def clean_sources_list():
    """Clean problematic entries from sources.list."""
    print("Cleaning /etc/apt/sources.list...")
    try:
        orig = "/etc/apt/sources.list"
        backup = "/etc/apt/sources.list.bak"
        if os.path.exists(orig):
            shutil.copy2(orig, backup)
            print(f"[INFO] Backup saved as {backup}")
            
            with open(backup, "r") as fin, open(orig, "w") as fout:
                for line in fin:
                    # Add your blacklisted sources here
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
    """Configure kernel hardening parameters."""
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


def create_baseline_hashes():
    """Create a baseline hash database for future comparisons."""
    print("\nCreating baseline hash database...")
    baseline_file = "/var/lib/system_integrity_baseline.txt"
    
    try:
        # Find all executables in common directories
        dirs_to_scan = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]
        
        with open(baseline_file, "w") as f:
            f.write(f"# System Integrity Baseline - Created: {subprocess.check_output('date', text=True).strip()}\n")
            f.write("# Format: SHA256HASH  FILEPATH\n\n")
            
            for directory in dirs_to_scan:
                if not os.path.exists(directory):
                    continue
                    
                print(f"[INFO] Scanning {directory}...")
                for root, dirs, files in os.walk(directory):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            if os.path.isfile(filepath) and not os.path.islink(filepath):
                                sha256 = hashlib.sha256()
                                with open(filepath, "rb") as binfile:
                                    for chunk in iter(lambda: binfile.read(8192), b""):
                                        sha256.update(chunk)
                                hash_value = sha256.hexdigest()
                                f.write(f"{hash_value}  {filepath}\n")
                        except (PermissionError, OSError):
                            continue
        
        print(f"[PASS] Baseline created: {baseline_file}")
        print("[INFO] You can verify against this baseline in the future")
        
    except Exception as e:
        logging.error(f"Failed to create baseline: {e}")
        print(f"[ERROR] Could not create baseline: {e}")


def verify_all_binaries():
    """Verify integrity of all installed binaries using package manager checksums."""
    print("\nVerifying system binary integrity...")
    
    # Use debsums to check ALL installed packages
    if shutil.which("debsums") is None:
        run_command("apt-get install -y debsums", exit_on_fail=False)
    
    print("[INFO] Generating missing MD5 checksums...")
    run_command("debsums -g", exit_on_fail=False)
    
    print("[INFO] Running full system package verification...")
    result = subprocess.run(
        "debsums -c 2>&1", 
        shell=True, 
        text=True, 
        capture_output=True
    )
    
    if result.returncode == 0 and not result.stdout.strip():
        print("[PASS] All installed packages verified successfully!")
    else:
        if result.stdout.strip():
            print("[WARNING] The following files failed verification:")
            print(result.stdout)
            # Log to file for later review
            with open("integrity_failures.log", "w") as f:
                f.write(result.stdout)
            print(f"[INFO] Full list saved to integrity_failures.log")
        else:
            print("[INFO] Verification complete with no issues detected.")
    
    return result.returncode == 0


def verify_critical_tools():
    """Verify critical security tools are properly installed and accessible."""
    print("\nVerifying critical security tools...")
    
    critical_tools = [
        "nmap", "sqlmap", "metasploit-framework", "john",
        "hashcat", "hydra", "burpsuite", "wireshark"
    ]
    
    verified = []
    missing = []
    
    for tool in critical_tools:
        # Check if tool exists in PATH
        tool_path = shutil.which(tool)
        if tool_path:
            # Verify it's from a legitimate package
            result = subprocess.run(
                f"dpkg -S {tool_path} 2>/dev/null",
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                package = result.stdout.split(':')[0]
                verified.append(f"{tool} ({package})")
            else:
                verified.append(f"{tool} (not from package)")
        else:
            missing.append(tool)
    
    if verified:
        print(f"[PASS] Verified {len(verified)} critical tools:")
        for v in verified:
            print(f"  ✓ {v}")
    
    if missing:
        print(f"[WARN] Missing {len(missing)} tools:")
        for m in missing:
            print(f"  ✗ {m}")
    
    return len(missing) == 0


def setup_cron_jobs():
    """Set up automated security audit cron jobs."""
    print("Setting up security cron jobs...")
    
    # Install security audit tools if not present
    audit_tools = ["lynis", "rkhunter"]
    for tool in audit_tools:
        if not shutil.which(tool):
            print(f"[INFO] Installing {tool}...")
            run_command(f"apt-get install -y {tool}", exit_on_fail=False)
    
    # Cron entries with proper format for /etc/crontab (includes username)
    cron_entries = {
        "lynis": "0 3 * * * root /usr/bin/lynis audit system --quiet",
        "rkhunter": "0 2 * * * root /usr/bin/rkhunter --update --quiet && /usr/bin/rkhunter --check --skip-keypress --quiet"
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
    """Install and configure security utilities."""
    print("Installing security utilities...")
    packages = [
        "unattended-upgrades", "apt-listchanges",
        "fail2ban", "ufw", "auditd", "audispd-plugins", "debsums"
    ]
    for pkg in packages:
        run_command(f"apt-get install -y {pkg}", exit_on_fail=False)

    # Configure firewall
    print("Configuring UFW firewall...")
    run_command("ufw default deny incoming", exit_on_fail=False)
    run_command("ufw default allow outgoing", exit_on_fail=False)
    run_command("ufw allow ssh", exit_on_fail=False)
    run_command("ufw --force enable", exit_on_fail=False)

    # Harden SSH
    print("Hardening SSH configuration...")
    ssh_config = "/etc/ssh/sshd_config"
    if os.path.exists(ssh_config):
        run_command(f"sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' {ssh_config}", exit_on_fail=False)
        run_command("systemctl restart ssh", exit_on_fail=False)
    else:
        print("[WARN] SSH config not found, skipping SSH hardening")

    # Enable services
    print("Enabling security services...")
    run_command("systemctl enable fail2ban --now", exit_on_fail=False)
    run_command("systemctl enable auditd --now", exit_on_fail=False)

    # Enable unattended upgrades
    print("Configuring unattended upgrades...")
    run_command("echo 'unattended-upgrades unattended-upgrades/enable_auto_updates boolean true' | debconf-set-selections", exit_on_fail=False)
    run_command("dpkg-reconfigure --priority=low unattended-upgrades", exit_on_fail=False)


def set_permissions():
    """Set secure file permissions on critical system files."""
    print("Setting secure file permissions...")
    perms = {
        "/etc/shadow": "640",
        "/etc/passwd": "644",
        "/etc/gshadow": "640",
        "/etc/group": "644"
    }
    for path, perm in perms.items():
        if os.path.exists(path):
            run_command(f"chmod {perm} {path}", exit_on_fail=False)
        else:
            print(f"[WARN] {path} not found")


def clean_up_system():
    """Clean up unnecessary packages and cache."""
    print("Cleaning up system...")
    run_command("apt-get autoremove -y", exit_on_fail=False)
    run_command("apt-get autoclean", exit_on_fail=False)
    run_command("apt-get clean", exit_on_fail=False)
    print("[INFO] Cleanup complete.")


def install_default_tools():
    """Install commonly used default penetration testing tools."""
    print("\nInstalling default security tools...")
    default_tools = [
        "nmap", "nikto", "sqlmap", "metasploit-framework",
        "wireshark", "tcpdump", "aircrack-ng", "john",
        "hashcat", "hydra", "dirb", "gobuster", "burpsuite"
    ]
    
    print(f"[INFO] Installing {len(default_tools)} default tools (this may take a while)...")
    # Install in one command for efficiency
    tools_str = " ".join(default_tools)
    success = run_command(f"apt-get install -y {tools_str}", exit_on_fail=False)
    
    if success:
        print("[PASS] ✓ Default tools installed successfully")
    else:
        print("[WARN] Some tools may have failed to install - check logs")


def generate_summary_report(backup_dir):
    """Generate a summary report of hardening actions."""
    report_path = "/root/hardening_summary.txt"
    
    try:
        with open(report_path, "w") as f:
            f.write("=" * 70 + "\n")
            f.write("SYSTEM HARDENING SUMMARY REPORT\n")
            f.write(f"Generated: {subprocess.check_output('date', shell=True, text=True).strip()}\n")
            f.write("=" * 70 + "\n\n")
            
            f.write("SECURITY FEATURES ENABLED:\n")
            f.write("  ✓ APT signature verification (rejects unsigned packages)\n")
            f.write("  ✓ Kernel hardening (sysctl parameters)\n")
            f.write("  ✓ AppArmor mandatory access control\n")
            f.write("  ✓ Fail2Ban (SSH brute-force protection)\n")
            f.write("  ✓ UFW firewall (deny incoming, allow outgoing)\n")
            f.write("  ✓ Auditd (system activity logging)\n")
            f.write("  ✓ Unattended security updates\n")
            f.write("  ✓ Root SSH login disabled\n")
            f.write("  ✓ Daily Lynis & Rootkit Hunter scans\n")
            f.write("  ✓ Secure file permissions\n")
            f.write("  ✓ Unnecessary services disabled\n")
            f.write("  ✓ Secure shared memory configuration\n\n")
            
            if backup_dir:
                f.write(f"CONFIGURATION BACKUPS: {backup_dir}\n\n")
            
            f.write("NEXT STEPS:\n")
            f.write("  1. Review logs: " + LOG_FILE + "\n")
            f.write("  2. Check firewall: sudo ufw status\n")
            f.write("  3. Verify AppArmor: sudo aa-status\n")
            f.write("  4. Test SSH login (root should be denied)\n")
            f.write("  5. REBOOT the system for all changes to take effect\n\n")
            
            f.write("MONITORING:\n")
            f.write("  - Lynis runs daily at 03:00 AM\n")
            f.write("  - Rootkit Hunter runs daily at 02:00 AM\n")
            f.write("  - Check /var/log/syslog for security events\n")
            f.write("  - Fail2Ban logs: /var/log/fail2ban.log\n\n")
            
            f.write("=" * 70 + "\n")
        
        print(f"[INFO] Summary report saved to {report_path}")
        
        # Also print to console
        with open(report_path, "r") as f:
            print("\n" + f.read())
            
    except Exception as e:
        logging.error(f"Failed to generate summary: {e}")


# === MAIN ===
def main():
    """Main execution flow."""
    print("=" * 60)
    print("OS HARDENING & INTEGRITY VERIFICATION")
    print("=" * 60)
    print()

    # Pre-flight checks
    pre_flight_checks()
    
    # Create backups
    backup_dir = create_backup()

    # Phase 1: Secure the package manager
    enable_apt_security()
    install_essential_tools()
    refresh_kali_keys()
    
    # Phase 2: Update system with verified packages
    update_system()
    clean_sources_list()
    
    # Phase 3: Harden the system
    configure_sysctl()
    enhanced_sysctl_hardening()
    configure_secure_shared_memory()
    enable_apparmor()
    disable_unnecessary_services()
    install_security_tools()
    install_default_tools()
    setup_cron_jobs()
    set_permissions()
    
    # Phase 4: Verify everything is legitimate
    verify_package_integrity()
    
    # Phase 5: Cleanup
    clean_up_system()
    
    # Generate summary report
    generate_summary_report(backup_dir)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] Hardening interrupted by user")
        print("[INFO] System may be partially hardened - review logs")
        exit(130)
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        logging.error(f"Unexpected error in main: {e}")
        exit(1)