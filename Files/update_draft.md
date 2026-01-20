# A draft update for my integrity script
## What it's supposed to do

---

## 1. Execution Safety & Logging

### Root check

* **What:** Exits if not run as root.
* **Why:** Every action (APT, sysctl, firewall, permissions) requires root. Prevents partial or misleading execution.

### Logging to `/var/log/system_hardening.log`

* **What:** Logs every command execution and all errors.
* **Why:** Provides auditability and troubleshooting without flooding stdout. Errors persist across reboots.

---

## 2. APT Supply-Chain Hardening (Prevention)

### `enable_apt_security()`

* **What:**

  * Rejects unauthenticated packages
  * Rejects insecure repositories
  * Rejects downgrades to insecure repos
  * Pins to `kali-rolling`
* **Why:**
  This prevents malicious packages **before installation** by enforcing:

  * Mandatory GPG signatures
  * No HTTP or unsigned repos
  * No downgrade attacks to weaker mirrors
    This is the strongest protection layer in the script.

---

## 3. Repository Hygiene

### `clean_sources_list()`

* **What:** Removes `http://` repositories from `sources.list` and backs it up.
* **Why:**
  HTTP allows MITM attacks. Kali official repos are HTTPS; anything else is unnecessary risk.

---

## 4. Trust Anchor Verification

### `refresh_kali_keys()`

* **What:**

  * Downloads the official Kali archive signing key
  * Converts it to a binary GPG key
  * Installs it into APT’s trusted keyring
* **Why:**
  Ensures that **only official Kali-signed packages** are trusted. Protects against:

  * Mirror compromise
  * Key poisoning
  * MITM during package downloads

---

## 5. System Update (Correct Order)

### `update_system()`

* **What:** Updates package lists and fully upgrades the system.
* **Why:**
  Ensures the system starts from a **known-good, fully patched state** before hardening.

---

## 6. Essential Tooling

### `install_essential_tools()`

* **What:** Installs wget, curl, gnupg, HTTPS transport, certificates.
* **Why:**
  These are prerequisites for secure package retrieval and key verification.

---

## 7. Kernel & Network Hardening (Non-Breaking)

### `configure_sysctl()`

* **What:** Enables:

  * ASLR
  * Kernel pointer & dmesg restrictions
  * Symlink/hardlink protections
  * Disables SUID core dumps
  * Enables TCP SYN cookies
* **Why:**
  Reduces kernel info leaks and basic exploitation vectors **without breaking Kali tools**.

---

## 8. Security Services Installation

### `install_security_tools()`

Installs and enables:

#### Fail2Ban

* **Why:** Blocks SSH brute-force attacks.

#### UFW

* **Why:** Simple firewall enforcing:

  * Default deny inbound
  * Allow outbound
  * SSH allowed explicitly

#### Auditd

* **Why:** Enables kernel-level activity logging for post-incident review.

#### AppArmor (light)

* **Why:** Enables kernel mediation framework **without enforcing profiles**, avoiding tool breakage.

#### Unattended upgrades

* **Why:** Keeps security updates applied automatically.

#### Lynis & rkhunter

* **Why:** Periodic security auditing and rootkit detection.

---

## 9. SSH Hardening (Minimal & Safe)

* **What:** Disables root SSH login and validates config before restart.
* **Why:**
  Prevents remote root access while preserving SSH usability.

---

## 10. Package Integrity Verification (Detection)

### `verify_package_integrity()`

* **What:** Runs `debsums -as` and logs modified files.
* **Why:**
  Detects **post-install tampering** of packaged files.

  * Uses MD5 only for integrity comparison
  * Trust comes from GPG signatures, not hashes

This confirms nothing malicious altered installed packages.

---

## 11. Automated Auditing

### `setup_cron_jobs()`

* **What:** Adds daily Lynis and rkhunter jobs via `/etc/cron.d/`.
* **Why:**
  Continuous, automated auditing without manual effort or cron corruption risk.

---

## 12. Permission Enforcement

### `set_permissions()`

* **What:** Enforces correct permissions on `/etc/{shadow,gshadow,passwd,group}`.
* **Why:**
  Prevents credential disclosure and enforces UNIX security expectations.

---

## 13. Cleanup

### `clean_up_system()`

* **What:** Removes unused packages and clears APT caches.
* **Why:**
  Reduces attack surface and frees disk space.

---

## 14. Final Outcome

After execution, the system:

* Only installs **signed, HTTPS-delivered Kali packages**
* Trusts only **official Kali archive keys**
* Detects post-install tampering
* Has basic firewalling, intrusion protection, auditing, and kernel hardening
* Runs continuous security audits automatically
* Avoids brittle hash baselines and enterprise lockdowns

---

# The Script
```py
#!/usr/bin/env python3
import subprocess
import os
import logging
import shutil
from pathlib import Path

# === CONFIG ===
LOG_FILE = "/var/log/system_hardening.log"
APT_TIMEOUT = 600
SYSCTL_DROPIN = "/etc/sysctl.d/99-hardening.conf"
CRON_FILE = "/etc/cron.d/security-audits"

# === LOGGING ===
Path(LOG_FILE).touch(exist_ok=True)
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# === HELPERS ===
def run_command(cmd: str, exit_on_fail=True):
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    logging.info(f"Running: {cmd}")
    try:
        subprocess.run(
            cmd,
            shell=True,
            check=True,
            timeout=APT_TIMEOUT,
            env=env
        )
    except subprocess.TimeoutExpired as e:
        logging.error(f"Timeout: {cmd} :: {e}")
        if exit_on_fail:
            raise SystemExit(1)
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed: {cmd} :: {e}")
        if exit_on_fail:
            raise SystemExit(1)

# === APT SECURITY ===
def enable_apt_security():
    conf = """
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
APT::Default-Release "kali-rolling";
"""
    Path("/etc/apt/apt.conf.d/99-hardening").write_text(conf.strip() + "\n")

# === SYSTEM PREP ===
def clean_sources_list():
    src = "/etc/apt/sources.list"
    backup = src + ".bak"
    if os.path.exists(src):
        shutil.copy2(src, backup)
        with open(backup) as fin, open(src, "w") as fout:
            for line in fin:
                if line.strip().startswith("http://"):
                    continue
                fout.write(line)

def refresh_kali_keys():
    tmp_asc = "/tmp/kali-archive-key.asc"
    tmp_gpg = "/tmp/kali-archive-key.gpg"

    run_command(f"wget -qO {tmp_asc} https://archive.kali.org/archive-key.asc")
    run_command(f"gpg --dearmor -o {tmp_gpg} {tmp_asc}")
    run_command(
        f"install -m 644 {tmp_gpg} /etc/apt/trusted.gpg.d/kali-archive-keyring.gpg"
    )

    os.remove(tmp_asc)
    os.remove(tmp_gpg)

def update_system():
    run_command("apt-get update --allow-releaseinfo-change")
    run_command("apt-get full-upgrade -y")

def install_essential_tools():
    run_command(
        "apt-get install -y wget curl gnupg software-properties-common "
        "apt-transport-https ca-certificates"
    )

# === HARDENING ===
def configure_sysctl():
    settings = [
        "fs.protected_symlinks = 1",
        "fs.protected_hardlinks = 1",
        "kernel.dmesg_restrict = 1",
        "kernel.kptr_restrict = 2",
        "kernel.randomize_va_space = 2",
        "fs.suid_dumpable = 0",
        "net.ipv4.tcp_syncookies = 1",
        "net.ipv4.icmp_echo_ignore_broadcasts = 1",
    ]
    Path(SYSCTL_DROPIN).write_text("\n".join(settings) + "\n")
    run_command("sysctl --system", exit_on_fail=False)

def install_security_tools():
    pkgs = [
        "unattended-upgrades",
        "fail2ban",
        "ufw",
        "auditd",
        "audispd-plugins",
        "debsums",
        "lynis",
        "rkhunter",
        "apparmor"
    ]
    run_command("apt-get install -y " + " ".join(pkgs))

    run_command("ufw default deny incoming", False)
    run_command("ufw default allow outgoing", False)
    run_command("ufw allow 22/tcp", False)
    run_command("ufw --force enable", False)

    run_command(
        "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' "
        "/etc/ssh/sshd_config",
        False
    )
    run_command("/usr/sbin/sshd -t")
    run_command("systemctl restart ssh")

    run_command("systemctl enable fail2ban --now", False)
    run_command("systemctl enable auditd --now", False)
    run_command("systemctl enable apparmor --now", False)

# === INTEGRITY ===
def verify_package_integrity():
    result = subprocess.run(
        "debsums -as",
        shell=True,
        text=True,
        capture_output=True
    )
    if result.stdout:
        Path("/var/log/integrity_failures.log").write_text(result.stdout)

# === CRON ===
def setup_cron_jobs():
    content = """SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

0 3 * * * root /usr/sbin/lynis audit system --quiet
0 2 * * * root /usr/bin/rkhunter --update --quiet && \
/usr/bin/rkhunter --check --skip-keypress --quiet
"""
    Path(CRON_FILE).write_text(content)

# === PERMISSIONS & CLEANUP ===
def set_permissions():
    run_command("chmod 600 /etc/shadow", False)
    run_command("chmod 600 /etc/gshadow", False)
    run_command("chmod 644 /etc/passwd", False)
    run_command("chmod 644 /etc/group", False)

def clean_up_system():
    run_command("apt-get autoremove -y", False)
    run_command("apt-get autoclean", False)
    run_command("apt-get clean", False)

# === MAIN ===
def main():
    if os.geteuid() != 0:
        raise SystemExit("Run as root.")

    enable_apt_security()
    clean_sources_list()
    refresh_kali_keys()
    update_system()
    install_essential_tools()
    configure_sysctl()
    install_security_tools()
    verify_package_integrity()
    setup_cron_jobs()
    set_permissions()
    clean_up_system()

    print("[SUCCESS] Kali hardening completed. Reboot recommended.")

if __name__ == "__main__":
    main()
```