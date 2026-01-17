#!/usr/bin/env bash

# Debian Express Secure
# Security & Hardening Script
# License: MIT
# Description: Secures and hardens Debian-based servers

# Define colors and formatting
RD="\033[01;31m"
GN="\033[0;32m"
YW="\033[33m"
BL="\033[0;34m"
CL="\033[m"
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${YW}→${CL}"
HIGHLIGHT="${BL}"

# Create temporary directory
TEMP_DIR="/tmp/debian-express"
SUMMARY_FILE="$TEMP_DIR/security-summary.txt"
mkdir -p "$TEMP_DIR"
touch "$SUMMARY_FILE"

# Cache system information
SERVER_IP=""
OS_NAME=""
OS_VERSION=""
OS_PRETTY=""

# Function to display success messages
msg_ok() {
  echo -e "${CM} $1"
  echo
}

# Function to display info messages
msg_info() {
  echo -e "${INFO} $1"
  echo
}

# Function to display error messages
msg_error() {
  echo -e "${CROSS} $1"
  echo
}

# Function to get yes/no input
get_yes_no() {
  local prompt="$1"
  local response

  while true; do
    echo -e -n "${prompt} [${HIGHLIGHT}y${CL}/${HIGHLIGHT}n${CL}]: "
    read -r response
    case $response in
      [Yy]* ) echo; return 0 ;;
      [Nn]* ) echo; return 1 ;;
      * ) echo "Please answer yes or no." ;;
    esac
  done
}

# Check root privileges
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    msg_error "This script must be run as root"
    exit 1
  fi
}

# Check Debian-based system
check_debian_based() {
  if [ ! -f /etc/debian_version ]; then
    msg_error "This script is designed for Debian-based systems only!"
    exit 1
  fi
}

# Detect OS version
detect_os() {
  if [ -f /etc/debian_version ]; then
    OS_VERSION=$(cat /etc/debian_version)
    if [ -f /etc/lsb-release ]; then
      OS_NAME="Ubuntu"
      OS_PRETTY=$(lsb_release -ds)
    else
      OS_NAME="Debian"
      OS_PRETTY="Debian ${OS_VERSION}"
    fi
    echo -e "Detected system: ${GN}${OS_PRETTY}${CL}\n"
    return 0
  else
    return 1
  fi
}

# Cache server IP
cache_server_ip() {
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
  fi
}

# Validate IP address or CIDR range
validate_ip_or_cidr() {
  local input="$1"

  # Check if it's a CIDR range
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
    local ip=$(echo "$input" | cut -d'/' -f1)
    local cidr=$(echo "$input" | cut -d'/' -f2)

    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
      if [ "$octet" -gt 255 ]; then
        return 1
      fi
    done

    if [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
      return 1
    fi

    return 0
  fi

  # Check if it's a simple IP
  if [[ "$input" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    IFS='.' read -ra OCTETS <<< "$input"
    for octet in "${OCTETS[@]}"; do
      if [ "$octet" -gt 255 ]; then
        return 1
      fi
    done
    return 0
  fi

  return 1
}

# Validate port number
validate_port() {
  local port="$1"
  if [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" -ge 1 ] && [ "$port" -le 65535 ]; then
    return 0
  fi
  return 1
}

# Display banner
display_banner() {
  clear
  cat <<"EOF"
 ____       _     _                _____
|  _ \  ___| |__ (_) __ _ _ __   | ____|_  ___ __  _ __ ___  ___ ___
| | | |/ _ \ '_ \| |/ _` | '_ \  |  _| \ \/ / '_ \| '__/ _ \/ __/ __|
| |_| |  __/ |_) | | (_| | | | | | |___ >  <| |_) | | |  __/\__ \__ \
|____/ \___|_.__/|_|\__,_|_| |_| |_____/_/\_\ .__/|_|  \___||___/___/
                                            |_|
  ____
 / ___|  ___  ___ _   _ _ __ ___
 \___ \ / _ \/ __| | | | '__/ _ \
  ___) |  __/ (__| |_| | | |  __/
 |____/ \___|\___|\__,_|_|  \___|

EOF

  echo -e "\n${BL}Security & Hardening${CL}\n"
}

###################
# SSH HARDENING
###################

configure_ssh_security() {
  if ! get_yes_no "Configure SSH security hardening?"; then
    msg_info "Skipping SSH hardening"
    echo "SSH hardening: Skipped" >> "$SUMMARY_FILE"
    return
  fi

  msg_info "Configuring SSH security..."

  # Install SSH if not present
  if ! command -v ssh > /dev/null; then
    msg_info "Installing SSH server..."
    apt install -y openssh-server
  fi

  # Backup config
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F) 2>/dev/null || true

  # Create config directory
  mkdir -p /etc/ssh/sshd_config.d

  # Check for non-root users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  current_user=$(whoami)

  # Create user if needed
  if [ "$current_user" = "root" ] && [ -z "$existing_users" ]; then
    msg_error "No non-root users detected"
    if get_yes_no "Create a non-root sudo user now? (Required before disabling root login)"; then
      echo -n "Enter username: "
      read -r new_username
      echo

      if [ -n "$new_username" ]; then
        adduser "$new_username"
        apt install -y sudo
        usermod -aG sudo "$new_username"
        msg_ok "User $new_username created with sudo privileges"
        existing_users="$new_username"
      fi
    fi
  fi

  # Disable root login
  if [ "$current_user" != "root" ] || [ -n "$existing_users" ]; then
    if get_yes_no "Disable root SSH login? (Highly recommended)"; then
      echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Root SSH login disabled"
      echo "Root SSH login: Disabled" >> "$SUMMARY_FILE"
    else
      echo "Root SSH login: Enabled" >> "$SUMMARY_FILE"
    fi
  fi

  # SSH key setup
  if get_yes_no "Set up SSH key authentication?"; then
    setup_ssh_keys
  else
    echo "SSH keys: Not configured" >> "$SUMMARY_FILE"
  fi

  # Enable public key auth
  echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
  echo "Public key authentication: Enabled" >> "$SUMMARY_FILE"

  # Check if SSH keys exist
  has_ssh_keys=false
  for user in $existing_users; do
    user_home=$(eval echo ~${user})
    if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
      has_ssh_keys=true
    fi
  done

  # Disable password authentication
  if [ "$has_ssh_keys" = true ]; then
    if get_yes_no "Disable password authentication? (Recommended when using SSH keys)"; then
      echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Password authentication disabled"
      echo "Password authentication: Disabled" >> "$SUMMARY_FILE"
    else
      echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
    fi
  else
    msg_info "Password authentication remains enabled (no SSH keys detected)"
    echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
  fi

  # Passwordless sudo
  if [ "$has_ssh_keys" = true ]; then
    if get_yes_no "Configure passwordless sudo? (Convenient when using SSH keys)"; then
      setup_passwordless_sudo
    fi
  fi

  # Restart SSH
  systemctl restart ssh

  # Show current config
  echo "SSH configuration applied:"
  echo
  sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication' | while IFS= read -r line; do
    key=$(echo "$line" | cut -d' ' -f1)
    value=$(echo "$line" | cut -d' ' -f2-)
    echo -e "$key ${HIGHLIGHT}$value${CL}"
  done
  echo

  msg_ok "SSH security configured"
}

# Setup SSH keys for user
setup_ssh_keys() {
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)

  if [ -z "$existing_users" ]; then
    msg_error "No non-system users found"
    return
  fi

  echo "Select user for SSH key setup:"
  echo

  user_num=1
  declare -A user_map
  for user in $existing_users; do
    echo -e "${HIGHLIGHT}$user_num${CL}) $user"
    user_map[$user_num]=$user
    ((user_num++))
  done

  echo
  echo -n "Enter user number: "
  read -r selected_num
  echo

  if [[ $selected_num =~ [0-9]+ && -n "${user_map[$selected_num]}" ]]; then
    username="${user_map[$selected_num]}"

    echo "To set up SSH key authentication for $username:"
    echo
    echo "1. On your LOCAL machine, generate a key (if you don't have one):"
    echo "   ssh-keygen -t ed25519 -C \"your-email@example.com\""
    echo
    echo "2. Copy your key to this server:"
    echo "   ssh-copy-id $username@$SERVER_IP"
    echo

    # Set up .ssh directory
    user_home=$(eval echo ~${username})
    mkdir -p ${user_home}/.ssh
    touch ${user_home}/.ssh/authorized_keys
    chmod 700 ${user_home}/.ssh
    chmod 600 ${user_home}/.ssh/authorized_keys
    chown -R ${username}:${username} ${user_home}/.ssh

    msg_ok "SSH directory created for $username"

    if get_yes_no "Have you copied your SSH key to the server?"; then
      if [ -s "${user_home}/.ssh/authorized_keys" ]; then
        msg_ok "SSH key detected for $username"
        echo "SSH keys: Configured for $username" >> "$SUMMARY_FILE"
      else
        msg_error "No SSH key found. Please copy your key before continuing."
      fi
    fi
  fi
}

# Setup passwordless sudo
setup_passwordless_sudo() {
  local current_user=$(logname 2>/dev/null || whoami)

  if groups "$current_user" | grep -q "\bsudo\b"; then
    echo "${current_user} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-${current_user}-nopasswd
    chmod 440 /etc/sudoers.d/99-${current_user}-nopasswd
    msg_ok "Passwordless sudo enabled for ${current_user}"
    echo "Passwordless sudo: Enabled for $current_user" >> "$SUMMARY_FILE"
  else
    msg_info "$current_user is not in sudo group"
    echo "Passwordless sudo: Not configured" >> "$SUMMARY_FILE"
  fi
}

###################
# FIREWALL SETUP
###################

configure_firewall() {
  if ! get_yes_no "Configure UFW firewall?"; then
    msg_info "Skipping firewall configuration"
    echo "Firewall (UFW): Not configured" >> "$SUMMARY_FILE"
    return
  fi

  # Install UFW
  if ! command -v ufw >/dev/null; then
    msg_info "Installing UFW..."
    apt install -y ufw
  fi

  ufw_status=$(ufw status | head -1)

  # Basic rules
  if get_yes_no "Apply basic firewall rules? (Allow SSH, deny incoming, allow outgoing)"; then
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp comment 'SSH'
    msg_ok "Basic firewall rules configured"
  fi

  # Web services
  echo "Allow web traffic?"
  echo
  echo -e "${HIGHLIGHT}1${CL}) HTTP (port 80)"
  echo -e "${HIGHLIGHT}2${CL}) HTTPS (port 443)"
  echo -e "${HIGHLIGHT}3${CL}) Both"
  echo -e "${HIGHLIGHT}4${CL}) None"
  echo
  echo -n "Enter option [1-4]: "
  read -r web_choice
  echo

  case $web_choice in
    1)
      ufw allow 80/tcp comment 'HTTP'
      msg_ok "HTTP allowed"
      ;;
    2)
      ufw allow 443/tcp comment 'HTTPS'
      msg_ok "HTTPS allowed"
      ;;
    3)
      ufw allow 80/tcp comment 'HTTP'
      ufw allow 443/tcp comment 'HTTPS'
      msg_ok "HTTP and HTTPS allowed"
      ;;
  esac

  # Custom ports
  if get_yes_no "Add custom firewall rules?"; then
    while true; do
      echo -n "Enter port number (1-65535, or press Enter to finish): "
      read -r port
      echo

      if [ -z "$port" ]; then
        break
      fi

      if validate_port "$port"; then
        echo "Select protocol:"
        echo -e "${HIGHLIGHT}1${CL}) TCP"
        echo -e "${HIGHLIGHT}2${CL}) UDP"
        echo -e "${HIGHLIGHT}3${CL}) Both"
        echo
        echo -n "Enter option [1-3]: "
        read -r proto_choice
        echo

        echo -n "Enter description: "
        read -r description
        echo

        case $proto_choice in
          1)
            ufw allow "$port"/tcp comment "$description"
            msg_ok "Port $port/tcp allowed"
            ;;
          2)
            ufw allow "$port"/udp comment "$description"
            msg_ok "Port $port/udp allowed"
            ;;
          *)
            ufw allow "$port" comment "$description"
            msg_ok "Port $port (tcp & udp) allowed"
            ;;
        esac
      else
        msg_error "Invalid port number"
      fi
    done
  fi

  # Enable firewall
  if [[ "$ufw_status" != *"active"* ]]; then
    if get_yes_no "Enable firewall now?"; then
      echo "y" | ufw enable
      msg_ok "Firewall enabled"
      echo "Firewall (UFW): Enabled" >> "$SUMMARY_FILE"
    else
      echo "Firewall (UFW): Configured but not enabled" >> "$SUMMARY_FILE"
    fi
  else
    if get_yes_no "Reload firewall configuration?"; then
      ufw reload
      msg_ok "Firewall reloaded"
      echo "Firewall (UFW): Active and reloaded" >> "$SUMMARY_FILE"
    fi
  fi

  echo
  echo "Current firewall rules:"
  ufw status verbose
  echo
}

###################
# FAIL2BAN SETUP
###################

setup_fail2ban() {
  if ! get_yes_no "Install and configure Fail2Ban? (Protects against brute-force attacks)"; then
    msg_info "Skipping Fail2Ban"
    echo "Fail2Ban: Not installed" >> "$SUMMARY_FILE"
    return
  fi

  msg_info "Installing Fail2Ban..."
  apt install -y fail2ban

  # Create basic config
  cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 5
ignoreip = 127.0.0.1 ::1
EOF

  # IP whitelist
  if get_yes_no "Add IPs to whitelist? (These IPs will never be banned)"; then
    echo "Enter IPs or CIDR ranges (space-separated):"
    echo "Examples: 192.168.1.5  10.0.0.0/24  192.168.0.0/16"
    echo
    echo -n "> "
    read -r whitelist_ips
    echo

    if [ -n "$whitelist_ips" ]; then
      valid_ips=""
      invalid_count=0

      for ip in $whitelist_ips; do
        if validate_ip_or_cidr "$ip"; then
          valid_ips="$valid_ips $ip"
        else
          msg_error "Invalid IP/CIDR: $ip (skipped)"
          ((invalid_count++))
        fi
      done

      if [ -n "$valid_ips" ]; then
        sed -i "s|ignoreip = 127.0.0.1 ::1|ignoreip = 127.0.0.1 ::1$valid_ips|" /etc/fail2ban/jail.local
        msg_ok "Whitelisted IPs:$valid_ips"
        echo "Fail2Ban whitelist:$valid_ips" >> "$SUMMARY_FILE"
      fi
    fi
  fi

  # SSH jail
  cat >> /etc/fail2ban/jail.local << EOF

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

  # Start service
  systemctl enable fail2ban
  systemctl restart fail2ban

  msg_ok "Fail2Ban installed and configured"
  echo "Fail2Ban: Active (bantime=600s, maxretry=5)" >> "$SUMMARY_FILE"

  sleep 2
  if systemctl is-active --quiet fail2ban; then
    fail2ban-client status sshd 2>/dev/null || msg_info "Fail2Ban is starting..."
  fi
}

###################
# VPN SETUP
###################

setup_vpn() {
  if ! get_yes_no "Set up a VPN? (Tailscale or Netbird)"; then
    msg_info "Skipping VPN setup"
    echo "VPN: Not configured" >> "$SUMMARY_FILE"
    return
  fi

  echo "Select VPN provider:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Tailscale"
  echo -e "${HIGHLIGHT}2${CL}) Netbird"
  echo
  echo -n "Enter option [1-2]: "
  read -r vpn_choice
  echo

  case $vpn_choice in
    1) setup_tailscale ;;
    2) setup_netbird ;;
    *) msg_info "Invalid option. Skipping VPN." ;;
  esac
}

setup_tailscale() {
  msg_info "Installing Tailscale..."

  if ! curl -fsSL https://tailscale.com/install.sh | sh; then
    msg_error "Tailscale installation failed"
    return 1
  fi

  if get_yes_no "Do you have a Tailscale auth key?"; then
    echo -n "Enter auth key: "
    read -r auth_key
    echo
    tailscale up --authkey="$auth_key"
  else
    tailscale up
    msg_info "Please authenticate using the URL above"
  fi

  tailscale_ip=$(tailscale ip 2>/dev/null || echo "Unknown")
  msg_ok "Tailscale configured"
  echo "VPN: Tailscale" >> "$SUMMARY_FILE"
  echo "Tailscale IP: $tailscale_ip" >> "$SUMMARY_FILE"
}

setup_netbird() {
  msg_info "Installing Netbird..."

  if ! curl -fsSL https://pkgs.netbird.io/install.sh | sh; then
    msg_error "Netbird installation failed"
    return 1
  fi

  echo -n "Enter Netbird setup key: "
  read -r setup_key
  echo

  if [ -n "$setup_key" ]; then
    netbird up --setup-key "$setup_key"
    msg_ok "Netbird configured"
    echo "VPN: Netbird" >> "$SUMMARY_FILE"
  else
    msg_error "No setup key provided"
  fi
}

###################
# AUTO UPDATES
###################

setup_auto_updates() {
  if ! get_yes_no "Enable automatic security updates?"; then
    msg_info "Skipping automatic updates"
    echo "Automatic updates: Not configured" >> "$SUMMARY_FILE"
    return
  fi

  msg_info "Configuring automatic security updates..."
  apt install -y unattended-upgrades apt-listchanges

  cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  # Disable automatic reboot
  sed -i 's|^Unattended-Upgrade::Automatic-Reboot ".*"|Unattended-Upgrade::Automatic-Reboot "false"|' /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
  if ! grep -q "Unattended-Upgrade::Automatic-Reboot" /etc/apt/apt.conf.d/50unattended-upgrades; then
    echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
  fi

  systemctl restart unattended-upgrades

  msg_ok "Automatic security updates enabled"
  echo "Automatic updates: Enabled (no auto-reboot)" >> "$SUMMARY_FILE"
}

#########################
# SUMMARY
#########################

display_security_summary() {
  cache_server_ip

  echo
  echo "=== Debian Express Security Summary ==="
  echo
  echo "System Information:"
  echo -e "• Hostname: ${HIGHLIGHT}$(hostname)${CL}"
  echo -e "• IP Address: ${HIGHLIGHT}$SERVER_IP${CL}"
  echo -e "• OS: ${HIGHLIGHT}$OS_PRETTY${CL}"
  echo

  echo "Security Configuration:"
  while IFS= read -r line; do
    echo -e "• ${HIGHLIGHT}$line${CL}"
  done < "$SUMMARY_FILE"

  echo
  echo "Summary saved to: /root/debian-express-security-summary.txt"
  echo

  # Save to file
  {
    echo "=== Debian Express Security Summary ==="
    echo
    echo "System: $(hostname) - $SERVER_IP"
    echo "OS: $OS_PRETTY"
    echo
    cat "$SUMMARY_FILE"
  } > /root/debian-express-security-summary.txt

  chmod 600 /root/debian-express-security-summary.txt
}

finalize_security_setup() {
  msg_info "Finalizing security setup..."

  apt autoremove -y > /dev/null 2>&1
  apt clean

  display_security_summary

  msg_ok "Security hardening completed!"
  echo
  echo "Your server has been secured."
  echo
  echo "IMPORTANT: Test SSH access in a new terminal before closing this session!"
  echo

  if get_yes_no "Reboot now to apply all changes?"; then
    echo "Rebooting in 5 seconds..."
    sleep 5
    reboot
  fi
}

###################
# MAIN
###################

main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  cache_server_ip

  if ! get_yes_no "This script will harden your server security. Proceed?"; then
    echo "Security hardening cancelled."
    exit 0
  fi

  configure_ssh_security
  configure_firewall
  setup_fail2ban
  setup_vpn
  setup_auto_updates

  finalize_security_setup
}

main "$@"
