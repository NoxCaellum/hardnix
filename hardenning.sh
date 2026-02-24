#!/bin/bash

#############################################################################
### Author: NoxCaellum
### Date: 02/20/2026
### This is an hardening script for Linux systems - Ubuntu
#############################################################################

ERROR="\e[31m"  
WARNING="\e[33m"  
SUCCESS="\e[32m"  
IMPORTANT="\033[35m"  
INFO="\033[36m"     
RESET="\e[0m"     

backup_files="/etc/pam.d/common-password /etc/default/grub"
CRON_FILE="/etc/cron.d/hardnix_detection"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT_DIR="."
 

Help() {
    cat <<EOF
HardNIX Help Menu
========================

Command        Description
-------        -----------
-h             Show this help menu
-m <level>     Set hardening level (minimal | intermediate | reinforced | elevated)

Hardening Levels (MIRE):
------------------------------------------------
Minimal      : Basic security hardening.
               - Implements essential protections.
               - Recommended for users' systems, test environments, or low-risk workstations.
Intermediate : Medium security hardening.
               - Adds additional measures.
               - Suitable for standard servers and production workstations with moderate exposure.
Reinforced   : Strong hardening.
               - Extends intermediate with stricter kernel parameters, service minimization, and tighter system policies.
               - Appropriate for sensitive servers handling critical data.
Elevated     : Maximum security hardening.
               - Includes all reinforced measures plus maximum restrictions, advanced auditing, and intrusion detection.
               - Designed for high-risk environments.

Examples: run this as root only
  hardnix.sh -m minimal
  hardnix.sh -m intermediate
  hardnix.sh -m reinforced
  hardnix.sh -m elevated
EOF
}



Report_generation() {
    TEMPLATE="$SCRIPT_DIR/report_template.html"
    OUTPUT="$REPORT_DIR/hardnix_report.html"

    mkdir -p "$REPORT_DIR"
    chmod 755 "$REPORT_DIR"
    

    DATE=$(date '+%Y-%m-%d %H:%M:%S')
    HOSTNAME=$(hostname)
    DISTRIBUTION=$(lsb_release -ds 2>/dev/null || grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '"')
    KERNEL=$(uname -r)

    KERNEL_CONFIG=$(sysctl -a 2>/dev/null)
    APPARMOR_STATUS=$(aa-status 2>/dev/null || echo "AppArmor not installed or disabled")

    PAM_RULES=$(grep -E 'pam_unix|pam_pwquality|pam_pwcheck' /etc/pam.d/common-password 2>/dev/null)
    FIREWALL_RULES=$(ufw status verbose 2>/dev/null || echo "UFW not enabled")


    FILE_BACKUPS=$(for f in $backup_files; do
        [[ -f "$f.bak" ]] && echo "Backup created: $f.bak"
    done)

    STICKY_FIXES=$(find / -type d -perm -0002 ! -uid 0 -exec ls -ld {} \; 2>/dev/null)
    SETUID_REMOVED=$(find / -type f -perm /6000 -exec ls -l {} \; 2>/dev/null)
    CRON_STATUS=$(ls -l "$CRON_FILE" 2>/dev/null)

    case "$hardening" in
        minimal)
            SCORE_CLASS="score-minimal"
            SCORE_MAX=100
            ;;
        intermediate)
            SCORE_CLASS="score-intermediate"
            SCORE_MAX=200
            ;;
        reinforced)
            SCORE_CLASS="score-reinforced"
            SCORE_MAX=300
            ;;
        elevated)
            SCORE_CLASS="score-elevated"
            SCORE_MAX=400
            ;;
        *)
            SCORE_CLASS="score-minimal"
            SCORE_MAX=100
            ;;
    esac

    APPLIED_ACTIONS=0
    [[ -n "$FILE_BACKUPS"        ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$STICKY_FIXES"        ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$SETUID_REMOVED"      ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$CRON_STATUS"         ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$FIREWALL_RULES"      ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$PAM_RULES"           ]] && ((APPLIED_ACTIONS+=1))
    [[ -n "$INSTALLED_PACKAGES"  ]] && ((APPLIED_ACTIONS+=1))
    SCORE_PERCENT=$((APPLIED_ACTIONS * 100 / 8))

    if   [[ $SCORE_PERCENT -ge 90 ]]; then SCORE_LABEL="Compliant"
    elif [[ $SCORE_PERCENT -ge 70 ]]; then SCORE_LABEL="Hardened"
    elif [[ $SCORE_PERCENT -ge 50 ]]; then SCORE_LABEL="Partial"
    else                                   SCORE_LABEL="Weak"
    fi

    if [[ ! -f "$TEMPLATE" ]]; then
        echo -e "${ERROR}[!] Template $TEMPLATE not found${RESET}"
        return 1
    fi

    cp "$TEMPLATE" "$OUTPUT"

    _esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/&/\\&/g' | tr '\n' '\1' | sed 's/\x01/\\n/g'; }

    sed -i "s|{{DATE}}|$(_esc "$DATE")|"                        "$OUTPUT"
    sed -i "s|{{HOSTNAME}}|$(_esc "$HOSTNAME")|"                "$OUTPUT"
    sed -i "s|{{DISTRIBUTION}}|$(_esc "$DISTRIBUTION")|"        "$OUTPUT"
    sed -i "s|{{KERNEL}}|$(_esc "$KERNEL")|"                    "$OUTPUT"
    sed -i "s|{{HARDENING_MODE}}|$(_esc "$hardening")|"         "$OUTPUT"
    sed -i "s|{{SCORE_CLASS}}|$(_esc "$SCORE_CLASS")|"          "$OUTPUT"
    sed -i "s|{{SCORE_PERCENT}}|$(_esc "$SCORE_PERCENT")|"      "$OUTPUT"
    sed -i "s|{{SCORE_LABEL}}|$(_esc "$SCORE_LABEL")|"          "$OUTPUT"
    sed -i "s|{{KERNEL_CONFIG}}|$(_esc "$KERNEL_CONFIG")|"      "$OUTPUT"
    sed -i "s|{{APPARMOR_STATUS}}|$(_esc "$APPARMOR_STATUS")|"  "$OUTPUT"
    sed -i "s|{{PAM_RULES}}|$(_esc "$PAM_RULES")|"              "$OUTPUT"
    sed -i "s|{{FIREWALL_RULES}}|$(_esc "$FIREWALL_RULES")|"    "$OUTPUT"
    sed -i "s|{{FILE_BACKUPS}}|$(_esc "$FILE_BACKUPS")|"        "$OUTPUT"
    sed -i "s|{{STICKY_FIXES}}|$(_esc "$STICKY_FIXES")|"        "$OUTPUT"
    sed -i "s|{{SETUID_REMOVED}}|$(_esc "$SETUID_REMOVED")|"    "$OUTPUT"
    sed -i "s|{{ANACRON_STATUS}}|$(_esc "$CRON_STATUS")|"       "$OUTPUT"

    chmod 644 "$OUTPUT"
    chown "$user":"$user" "$OUTPUT"
    echo -e "${SUCCESS}[+] Report generated: $(realpath "$OUTPUT")${RESET}"
}


Apply_base_hardening() {
    local level="$1"

    echo -e "${INFO}[-] --- Base hardening applied for level: $level ---${RESET}"

    for f in $backup_files; do
        echo -e "${IMPORTANT}[-] Creating backup of $f${RESET}"
        cp "$f" "$f.bak"
    done
    echo -e "[*] Enabling firewall..."
    ufw enable
    ufw logging on
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 443/tcp
    echo -e "${IMPORTANT}[-] Check the firewall configuration with: ufw status verbose${RESET}"

    echo -e "${INFO}========== Base Account Configuration ==========${RESET}"

    echo -e "${IMPORTANT}[*] Do not forget to add an expiration date to local accounts${RESET}"
    echo -e "${IMPORTANT}[*] Do not use root for administration tasks; configure dedicated administrator accounts${RESET}"

    echo -e "${IMPORTANT}[-] Applying password policy: /etc/pam.d/common-password${RESET}"
    sed -i '/^password\s\+\[success=2 default=ignore\]\s\+pam_unix\.so/ s/$/ minlen=8/' \
        /etc/pam.d/common-password
    echo -e "${SUCCESS}[+] Minimum password length set to 8${RESET}"
    echo -e "[*] Searching for files with no known owner or group:"
    find / -type f \( -nouser -o -nogroup \) -ls 2>/dev/null
    echo -e "${WARNING}[*] It is recommended to remove or reassign files without owners${RESET}"

    echo -e "[*] Setting sticky bit on world-writable directories not owned by root..."
    find / -type d -perm -0002 -a \! -uid 0 -exec chmod +t {} \; 2>/dev/null

    echo -e "[*] Removing SETUID and SETGID special permissions..."
    find / -type f -perm /6000 -exec chmod u-s {} \; 2>/dev/null
    find / -type f -perm /6000 -exec chmod g-s {} \; 2>/dev/null

    echo -e "[*] Listing installed services (saved to installed_service.txt):"
    systemctl list-units --type=service >> installed_service.txt
    echo -e "${IMPORTANT}[-] Please review and disable any unnecessary services: installed_service.txt${RESET}"
}


Apply_intermediate_hardening() {
    local level="$1"

    echo -e "${INFO}[-] --- Intermediate hardening applied for level: $level ---${RESET}"

    echo -e "${INFO}========== Intermediate Account Configuration ==========${RESET}"

    echo "[*] Automatic logout after 15 minutes of inactivity"
    sed -i '/^TMOUT=/d' /etc/profile
    echo "TMOUT=900" >> /etc/profile
    echo "readonly TMOUT" >> /etc/profile
    echo "export TMOUT" >> /etc/profile


    echo "[*] Auditd configuration for command logging"
    echo "-a exit,always -F arch=b64 -S execve -k root-commands" >> /etc/auditd/audit.rules
    echo "-a exit,always -F arch=b32 -S execve -k root-commands" >> /etc/auditd/audit.rules
    echo "[*] Restarting auditd service"
    service auditd restart
    echo -e "${IMPORTANT}[-] Auditd rules file: /etc/auditd/audit.rules${RESET}"
    echo -e "${IMPORTANT}[-] This method generates a lot of logs; please configure a log export routine${RESET}"
    echo -e "${SUCCESS}[+] Auditd logging configuration activated${RESET}"

    echo -e "${IMPORTANT}[-] Please delete all service accounts that are not dedicated${RESET}"
    echo -e "${IMPORTANT}[-] Please configure a dedicated service account for each added service${RESET}"

    echo "[*] Sudoers configuration - adding: noexec, requiretty, use_pty, umask=0027, ignore_dot, env_reset to sudoers defaults"
    echo "Defaults noexec,requiretty,use_pty,umask=0027" >> /etc/sudoers
    echo "Defaults ignore_dot,env_reset" >> /etc/sudoers
    echo -e "${SUCCESS}[+] Default rules successfully added to /etc/sudoers${RESET}"


    echo -e "${INFO}========== Intermediate Kernel Configuration ==========${RESET}"

    echo "[*] Activate page poisoning (page_poison=on)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ page_poison=on"/' /etc/default/grub

    echo "[*] Enable Page Table Isolation (pti=on)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ pti=on"/' /etc/default/grub

    echo "[*] Disable slab merging (slab_nomerge=yes)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ slab_nomerge=yes"/' /etc/default/grub

    echo "[*] Enable SLUB debug options (slub_debug=FZP)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ slub_debug=FZP"/' /etc/default/grub

    echo "[*] Disable speculative store bypass (spec_store_bypass_disable=seccomp)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ spec_store_bypass_disable=seccomp"/' /etc/default/grub

    echo "[*] Enable Spectre v2 mitigation (spectre_v2=on)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ spectre_v2=on"/' /etc/default/grub

    echo "[*] Enable MDS mitigation with SMT disabled (mds=full,nosmt)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ mds=full,nosmt"/' /etc/default/grub

    echo "[*] Force kernel panic on Machine Check Exception (mce=0)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ mce=0"/' /etc/default/grub

    echo "[*] Enable page allocator randomization (page_alloc.shuffle=1)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ page_alloc.shuffle=1"/' /etc/default/grub

    echo "[*] Increase HWRNG quality for CSPRNG initialization (rng_core.default_quality=500)"
    sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT="/ s/"$/ rng_core.default_quality=500"/' /etc/default/grub


    echo -e "${INFO}[*] Protect the kernel cmdline parameters and initramfs${RESET}"

    echo "[*] Disable SysRq"
    sed -i '/^kernel.sysrq/d' /etc/sysctl.conf
    echo "kernel.sysrq=0" >> /etc/sysctl.conf

    echo "[*] Disable core dumps for SUID binaries"
    sed -i '/^fs.suid_dumpable/d' /etc/sysctl.conf
    echo "fs.suid_dumpable=0" >> /etc/sysctl.conf

    echo "[*] Patch symlink and hardlink TOCTOU race conditions"
    sed -i '/^fs.protected_symlinks/d' /etc/sysctl.conf
    echo "fs.protected_symlinks=1" >> /etc/sysctl.conf
    sed -i '/^fs.protected_hardlinks/d' /etc/sysctl.conf
    echo "fs.protected_hardlinks=1" >> /etc/sysctl.conf

    echo "[*] Enable ASLR"
    sed -i '/^kernel.randomize_va_space/d' /etc/sysctl.conf
    echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf

    echo "[*] Disable low address space mapping"
    sed -i '/^vm.mmap_min_addr/d' /etc/sysctl.conf
    echo "vm.mmap_min_addr=65536" >> /etc/sysctl.conf

    echo "[*] Increase PID limit"
    sed -i '/^kernel.pid_max/d' /etc/sysctl.conf
    echo "kernel.pid_max=65536" >> /etc/sysctl.conf

    echo "[*] Obfuscate kernel memory addresses"
    sed -i '/^kernel.kptr_restrict/d' /etc/sysctl.conf
    echo "kernel.kptr_restrict=1" >> /etc/sysctl.conf

    echo "[*] Restrict access to dmesg buffer"
    sed -i '/^kernel.dmesg_restrict/d' /etc/sysctl.conf
    echo "kernel.dmesg_restrict=1" >> /etc/sysctl.conf

    echo "[*] Restrict perf subsystem"
    sed -i '/^kernel.perf_event_paranoid/d' /etc/sysctl.conf
    echo "kernel.perf_event_paranoid=2" >> /etc/sysctl.conf
    sed -i '/^kernel.perf_event_max_sample_rate/d' /etc/sysctl.conf
    echo "kernel.perf_event_max_sample_rate=1" >> /etc/sysctl.conf
    sed -i '/^kernel.perf_cpu_time_max_percent/d' /etc/sysctl.conf
    echo "kernel.perf_cpu_time_max_percent=1" >> /etc/sysctl.conf

    echo "[*] Stop system on kernel oops"
    sed -i '/^kernel.panic_on_oops/d' /etc/sysctl.conf
    echo "kernel.panic_on_oops=1" >> /etc/sysctl.conf

    echo "[*] Enable Yama ptrace protection"
    sed -i '/^kernel.yama.ptrace_scope/d' /etc/sysctl.conf
    echo "kernel.yama.ptrace_scope=1" >> /etc/sysctl.conf

    echo -e "${INFO}IPv4 configuration...${RESET}"

    echo "[*] Mitigate BPF JIT spray attacks"
    sed -i '/^net.core.bpf_jit_harden/d' /etc/sysctl.conf
    echo "net.core.bpf_jit_harden=2" >> /etc/sysctl.conf

    echo "[*] Disable IPv4 forwarding"
    sed -i '/^net.ipv4.ip_forward/d' /etc/sysctl.conf
    echo "net.ipv4.ip_forward=0" >> /etc/sysctl.conf

    echo "[*] Disable IPv6"
    sed -i '/^net.ipv6.conf.default.disable_ipv6=1/d' /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6=1" >> /etc/sysctl.conf
    sed -i '/^net.ipv6.conf.all.disable_ipv6=1/d' /etc/sysctl.conf
    echo "net.ipv6.conf.all.disable_ipv6=1" >> /etc/sysctl.conf

    echo "[*] Treat external packets with a local source address as invalid"
    sed -i '/^net.ipv4.conf.all.accept_local/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_local=0" >> /etc/sysctl.conf

    echo "[*] Disable ICMP redirects and shared media redirects"
    sed -i '/^net.ipv4.conf.all.accept_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.default.accept_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.all.secure_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.default.secure_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.all.shared_media/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.shared_media=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.default.shared_media/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.shared_media=0" >> /etc/sysctl.conf

    echo "[*] Disable source routing"
    sed -i '/^net.ipv4.conf.all.accept_source_route/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.default.accept_source_route/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.conf

    echo "[*] Prevent global ARP responses across interfaces"
    sed -i '/^net.ipv4.conf.all.arp_filter/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.arp_filter=1" >> /etc/sysctl.conf

    echo "[*] Restrict ARP replies to the matching interface"
    sed -i '/^net.ipv4.conf.all.arp_ignore/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.arp_ignore=2" >> /etc/sysctl.conf

    echo "[*] Disable routing of localhost traffic"
    sed -i '/^net.ipv4.conf.all.route_localnet/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.route_localnet=0" >> /etc/sysctl.conf

    echo "[*] Drop gratuitous ARP packets"
    sed -i '/^net.ipv4.conf.all.drop_gratuitous_arp/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.drop_gratuitous_arp=1" >> /etc/sysctl.conf

    echo "[*] Enable reverse path filtering (anti-spoofing)"
    sed -i '/^net.ipv4.conf.default.rp_filter/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.all.rp_filter/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.conf

    echo "[*] Disable sending ICMP redirects"
    sed -i '/^net.ipv4.conf.default.send_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.conf
    sed -i '/^net.ipv4.conf.all.send_redirects/d' /etc/sysctl.conf
    echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.conf

    echo "[*] Ignore bogus ICMP error responses"
    sed -i '/^net.ipv4.icmp_ignore_bogus_error_responses/d' /etc/sysctl.conf
    echo "net.ipv4.icmp_ignore_bogus_error_responses=1" >> /etc/sysctl.conf

    echo "[*] Set ephemeral port range"
    sed -i '/^net.ipv4.ip_local_port_range/d' /etc/sysctl.conf
    echo "net.ipv4.ip_local_port_range=32768 65535" >> /etc/sysctl.conf

    echo "[*] Enable RFC 1337 protection"
    sed -i '/^net.ipv4.tcp_rfc1337/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.conf

    echo "[*] Enable TCP SYN cookies"
    sed -i '/^net.ipv4.tcp_syncookies/d' /etc/sysctl.conf
    echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.conf

    echo -e "${INFO}File system configuration${RESET}"

    echo "[*] Disable SUID core dumps"
    sed -i '/^fs.suid_dumpable/d' /etc/sysctl.conf
    echo "fs.suid_dumpable=0" >> /etc/sysctl.conf

    echo "[*] Restrict FIFO access in world-writable sticky directories"
    sed -i '/^fs.protected_fifos/d' /etc/sysctl.conf
    echo "fs.protected_fifos=2" >> /etc/sysctl.conf

    echo "[*] Restrict regular file access in world-writable sticky directories"
    sed -i '/^fs.protected_regular/d' /etc/sysctl.conf
    echo "fs.protected_regular=2" >> /etc/sysctl.conf

    echo "[*] Restrict symbolic link creation (TOCTOU protection)"
    sed -i '/^fs.protected_symlinks/d' /etc/sysctl.conf
    echo "fs.protected_symlinks=1" >> /etc/sysctl.conf

    echo "[*] Restrict hard link creation (TOCTOU protection)"
    sed -i '/^fs.protected_hardlinks/d' /etc/sysctl.conf
    echo "fs.protected_hardlinks=1" >> /etc/sysctl.conf


    sysctl -p
    echo -e "${SUCCESS}[*] Kernel hardening changes have been made persistent${RESET}"
    echo -e "${IMPORTANT}[-] You can review the sysctl configuration at: /etc/sysctl.conf or with 'sysctl -a'${RESET}"
}


Apply_reinforced_hardening() {
    local level="$1"

    echo -e "${INFO}[-] --- Reinforced hardening applied for level: $level ---${RESET}"

    echo -e "${INFO}========== Reinforced Account Configuration ==========${RESET}"

    echo -e "${IMPORTANT}[-] Do not specify access permissions by negation in /etc/sudoers; they can be easily bypassed${RESET}"
    echo -e "${IMPORTANT}[-] All sudoers commands must specify their arguments explicitly; avoid using wildcards (*) in rules${RESET}"

    echo -e "${INFO}========== Reinforced Kernel Configuration ==========${RESET}"

    echo "[*] Activate IOMMU"
    sed -i 's/^GRUB_CMDLINE_LINUX_DEFAULT="/&iommu=force /' /etc/default/grub

    update-grub
    echo -e "${SUCCESS}[*] IOMMU has been activated - wait for the script to complete before rebooting${RESET}"

    echo "[*] Disable kernel modules loading"
    echo "kernel.modules_disabled=1" >> /etc/sysctl.conf
    echo -e "${IMPORTANT}[-] Kernel module list: /etc/modules${RESET}"
}


Apply_elevated_hardening() {
    local level="$1"

    echo -e "${INFO}[-] --- Elevated hardening applied for level: $level ---${RESET}"
    echo -e "${INFO}========== Elevated Kernel Configuration ==========${RESET}"
}


Hardening() {

    if [[ "$hardening" != "minimal"      && \
          "$hardening" != "intermediate" && \
          "$hardening" != "reinforced"   && \
          "$hardening" != "elevated"     ]]; then
        echo -e "${ERROR}[!] Invalid hardening level: '$hardening'${RESET}"
        Help
        exit 1
    fi


    if [[ "$hardening" == "minimal" ]]; then
        echo -e "${IMPORTANT}[-] Minimal hardening${RESET}"

        Apply_base_hardening "$hardening"


    elif [[ "$hardening" == "intermediate" ]]; then
        echo -e "${IMPORTANT}[-] Intermediate hardening${RESET}"

        Apply_base_hardening "$hardening"
        Apply_intermediate_hardening "$hardening"


    elif [[ "$hardening" == "reinforced" ]]; then
        echo -e "${IMPORTANT}[-] Reinforced hardening${RESET}"

        Apply_base_hardening "$hardening"
        Apply_intermediate_hardening "$hardening"
        Apply_reinforced_hardening "$hardening"


    elif [[ "$hardening" == "elevated" ]]; then
        echo -e "${IMPORTANT}[-] Elevated hardening${RESET}"

        Apply_base_hardening "$hardening"
        Apply_intermediate_hardening "$hardening"
        Apply_elevated_hardening "$hardening"
    fi
}


Audit() {
    Report_generation
}


main() {

    cat <<"EOF"
     /$$   /$$                           /$$           /$$
    | $$  | $$                          | $$          |__/
    | $$  | $$  /$$$$$$   /$$$$$$   /$$$$$$$ /$$$$$$$  /$$ /$$   /$$
    | $$$$$$$$ |____  $$ /$$__  $$ /$$__  $$| $$__  $$| $$|  $$ /$$/
    | $$__  $$  /$$$$$$$| $$  \__/| $$  | $$| $$  \ $$| $$ \  $$$$/
    | $$  | $$ /$$__  $$| $$      | $$  | $$| $$  | $$| $$  >$$  $$
    | $$  | $$|  $$$$$$$| $$      |  $$$$$$$| $$  | $$| $$ /$$/\  $$
    |__/  |__/ \_______/|__/       \_______/|__/  |__/|__/|__/  \__/
EOF

    echo -e "Run 'hardnix.sh -h' to display the help menu."
    echo "You local account will be use to be the owner of the reports"
    

    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${ERROR}[!] hardnix.sh must be run with root privileges${RESET}" >&2
        exit 1
    fi


    while getopts "hm:d" flag; do
        case "${flag}" in
            h) Help; exit 0 ;;
            m) hardening="${OPTARG}" ;;
        esac
    done


    if [[ "$#" -eq 0 ]]; then
        echo -e "${WARNING}[!] No argument provided${RESET}"
        Help
        exit 1
    fi

    read -p "Enter your local account: " user
    Hardening
    Audit

    echo -e "${IMPORTANT}[-] Reboot in 1 minute${RESET}"
    shutdown -h +1
}

main "$@"