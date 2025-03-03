#!/usr/bin/env bash

# Debian Express Setup
# Author: [Your Name]
# License: MIT
# Description: Automated setup and security configuration for Debian-based servers and VPS

# Define colors and formatting
RD=$(echo -e "\033[01;31m")
GN=$(echo -e "\033[1;92m")
YW=$(echo -e "\033[33m")
BL=$(echo -e "\033[1;34m")
CL=$(echo -e "\033[m")
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${YW}ℹ️${CL}"

# Function to display success messages
msg_ok() {
  echo -e "${CM} $1"
}

# Function to display info messages
msg_info() {
  echo -e "${INFO} $1"
}

# Function to display error messages
msg_error() {
  echo -e "${CROSS} $1"
}

# Ensure script exits on error
set -euo pipefail

# Function to set up system basics
setup_core_configuration() {
  msg_info "Starting core system configuration..."
  
  # System update and upgrade
  if whiptail --title "System Update" --yesno "Do you want to update and upgrade system packages?" 8 60; then
    msg_info "Updating and upgrading system packages..."
    apt update && apt upgrade -y
    msg_ok "System packages updated and upgraded"
  else
    msg_info "Skipping system update"
  fi
  
  # Hostname configuration
  current_hostname=$(hostname)
  new_hostname=$(whiptail --inputbox "Current hostname: $current_hostname\n\nEnter new hostname (leave empty to keep current):" 10 60 "$current_hostname" 3>&1 1>&2 2>&3)
  if [ $? -eq 0 ] && [ "$new_hostname" != "$current_hostname" ]; then
    hostnamectl set-hostname "$new_hostname"
    # Update /etc/hosts file
    sed -i "s/127.0.1.1.*$current_hostname/127.0.1.1\t$new_hostname/g" /etc/hosts
    msg_ok "Hostname changed to $new_hostname"
  else
    msg_info "Hostname unchanged"
  fi
  
  # Timezone setting
  current_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
  if whiptail --title "Timezone Configuration" --yesno "Current timezone: $current_timezone\n\nDo you want to change the timezone?" 10 60; then
    dpkg-reconfigure tzdata
    new_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    msg_ok "Timezone set to $new_timezone"
  else
    msg_info "Timezone unchanged"
  fi
  
  # Locale configuration
  current_locale=$(locale | grep LANG= | cut -d= -f2)
  # Get a more readable locale name
  case "$current_locale" in
    en_US.UTF-8) readable_locale="English (US) - $current_locale" ;;
    en_GB.UTF-8) readable_locale="English (UK) - $current_locale" ;;
    de_DE.UTF-8) readable_locale="German - $current_locale" ;;
    fr_FR.UTF-8) readable_locale="French - $current_locale" ;;
    es_ES.UTF-8) readable_locale="Spanish - $current_locale" ;;
    it_IT.UTF-8) readable_locale="Italian - $current_locale" ;;
    *) readable_locale="$current_locale" ;;
  esac

  if whiptail --title "Locale Configuration" --yesno "Current locale: $readable_locale\n\nDo you want to configure system locale?" 10 60; then
    dpkg-reconfigure locales
    new_locale=$(locale | grep LANG= | cut -d= -f2)
    msg_ok "Locale set to $new_locale"
  else
    msg_info "Locale unchanged"
  fi
  
  # Root password management
  if whiptail --title "Root Password" --yesno "Do you want to set/change the root password?" 8 60; then
    passwd root
    msg_ok "Root password updated"
  else
    msg_info "Root password unchanged"
  fi
  
  # Non-root user creation with sudo access
  # Get list of non-system users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort | tr '\n' ' ')
  if [ -z "$existing_users" ]; then
    existing_users="None"
  fi

  if whiptail --title "Create User" --yesno "Current non-system users: $existing_users\n\nDo you want to create a new non-root user with sudo access?" 10 70; then
    username=$(whiptail --inputbox "Enter username for the new user:" 8 60 3>&1 1>&2 2>&3)
    if [ $? -eq 0 ] && [ ! -z "$username" ]; then
      # Check if user already exists
      if id "$username" &>/dev/null; then
        if whiptail --title "User Exists" --yesno "User $username already exists.\n\nDo you want to modify this user instead?" 10 60; then
          # Continue with modification options
          msg_info "Proceeding with user modification"
        else
          msg_info "User creation/modification skipped"
        fi
      else
        adduser "$username"
        # Install sudo if not already installed
        apt install -y sudo
        # Add user to sudo group
        usermod -aG sudo "$username"
        msg_ok "User $username created and added to sudo group"
      fi
    else
      msg_info "User creation skipped"
    fi
  else
    msg_info "User creation skipped"
  fi
  
  msg_ok "Core configuration completed"
}

# Function to configure network security settings
configure_network_security() {
  msg_info "Configuring network security..."
  
  # SSH configuration
  configure_ssh_security
  
  # Setup Firewall (UFW)
  configure_firewall
  
  # Setup Fail2Ban
  setup_fail2ban
  
  # Setup VPN options (Netbird or Tailscale)
  setup_vpn
  
  msg_ok "Network security configuration completed"
}

# Function to configure SSH and security settings
configure_ssh_security() {
  msg_info "Configuring SSH and security settings..."
  
  # Check if SSH is installed
  if ! command -v ssh > /dev/null; then
    msg_info "Installing SSH server..."
    apt install -y openssh-server
  fi
  
  # Backup existing configuration
  cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%F)
  
  # SSH hardening options
  ssh_options=$(whiptail --title "SSH Security Options" --checklist \
    "Select SSH security options to configure:" 16 78 6 \
    "DISABLE_ROOT" "Disable root SSH login (recommended)" ON \
    "PUBKEY_AUTH" "Enable public key authentication (recommended)" ON \
    "DISABLE_PASSWORD" "Disable password authentication (requires SSH keys)" OFF \
    "CHANGE_PORT" "Change SSH port (advanced)" OFF \
    "LIMIT_USERS" "Limit SSH access to specific users" OFF \
    "SSH_KEYS" "Set up SSH keys for a user" ON 3>&1 1>&2 2>&3)

  # Process SSH options
  if [[ $? -eq 0 ]]; then
    # Create directory for custom SSH config
    mkdir -p /etc/ssh/sshd_config.d
    
    # Harden SSH configuration based on selected options
    if [[ $ssh_options == *"DISABLE_ROOT"* ]]; then
      echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Root SSH login disabled"
    fi
    
    if [[ $ssh_options == *"PUBKEY_AUTH"* ]]; then
      echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Public key authentication enabled"
    fi
    
    if [[ $ssh_options == *"DISABLE_PASSWORD"* ]]; then
      # Check if we're setting up SSH keys to prevent lockouts
      if [[ $ssh_options != *"SSH_KEYS"* ]]; then
        if ! whiptail --title "Security Warning" --yesno "You're about to disable password authentication without setting up SSH keys.\n\nThis could lock you out of your server if SSH keys aren't already configured.\n\nAre you sure you want to continue?" 12 78; then
          msg_info "Password authentication remains enabled"
        else
          echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-security.conf
          msg_ok "Password authentication disabled"
        fi
      else
        echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-security.conf
        msg_ok "Password authentication disabled"
      fi
    fi
    
    if [[ $ssh_options == *"CHANGE_PORT"* ]]; then
      port=$(whiptail --inputbox "Enter new SSH port number (between 1024-65535):" 8 60 "2222" 3>&1 1>&2 2>&3)
      if [[ $? -eq 0 && $port =~ ^[0-9]+$ && $port -gt 1023 && $port -lt 65536 ]]; then
        echo "Port $port" >> /etc/ssh/sshd_config.d/50-security.conf
        
        # Update firewall rules if UFW is installed
        if command -v ufw > /dev/null; then
          ufw allow $port/tcp comment 'SSH custom port'
          msg_info "UFW rule added for port $port/tcp"
        fi
        
        msg_ok "SSH port changed to $port"
      else
        msg_error "Invalid port. SSH port unchanged."
      fi
    fi
    
    if [[ $ssh_options == *"LIMIT_USERS"* ]]; then
      # Get list of non-system users
      existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
      
      # Format for whiptail checklist
      user_options=""
      for user in $existing_users; do
        user_options="$user_options $user User ON "
      done
      
      # Show user selection dialog
      selected_users=$(whiptail --title "Limit SSH Access" --checklist \
        "Select users allowed to access via SSH:" 16 60 8 $user_options 3>&1 1>&2 2>&3)
      
      if [[ $? -eq 0 && ! -z "$selected_users" ]]; then
        # Format the list correctly for sshd_config
        formatted_users=$(echo $selected_users | tr -d '"' | tr ' ' ',')
        echo "AllowUsers $formatted_users" >> /etc/ssh/sshd_config.d/50-security.conf
        msg_ok "SSH access limited to: $formatted_users"
      fi
    fi
    
    # Set up SSH keys for a user if selected
    if [[ $ssh_options == *"SSH_KEYS"* ]]; then
      setup_ssh_keys
    fi
    
    # After configuring SSH, ask about passwordless sudo
    # This is moved from the user creation section as suggested
    setup_passwordless_sudo
    
    # Restart SSH service
    systemctl restart ssh
    
    # Display current SSH configuration
    current_settings=$(sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication|port|allowusers')
    
    # Show final SSH settings
    whiptail --title "SSH Configuration Complete" --msgbox "SSH has been configured with the following settings:\n\n$current_settings\n\nKeep this terminal window open and verify you can connect with a new SSH session before closing." 16 78
    
    msg_ok "SSH configuration completed"
  else
    msg_info "SSH configuration skipped"
  fi
}

# Function to set up SSH keys for a user
setup_ssh_keys() {
  # Get list of non-system users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  
  # Format for whiptail menu
  user_options=""
  item_num=1
  for user in $existing_users; do
    user_options="$user_options $item_num $user "
    ((item_num++))
  done
  
  # Show user selection menu
  selected_user=$(whiptail --title "SSH Key Setup" --menu \
    "Select a user to set up SSH keys for:" 16 60 8 $user_options 3>&1 1>&2 2>&3)
  
  if [[ $? -eq 0 && ! -z "$selected_user" ]]; then
    username=$(echo $existing_users | tr ' ' '\n' | sed -n "${selected_user}p")
    
    # Show SSH key information and instructions
    if whiptail --title "SSH Key Setup Guide" --yesno \
      "To set up SSH key authentication for $username:\n\n1. ON YOUR LOCAL MACHINE, first generate an SSH key if you don't\n   already have one:\n\n   ssh-keygen -t ed25519 -C \"email@example.com\"\n   or\n   ssh-keygen -t rsa -b 4096 -C \"email@example.com\"\n\n2. Then copy your key to this server with:\n\n   ssh-copy-id $username@SERVER_IP\n\n3. Press <Yes> to prepare the server for SSH key authentication\n   or <No> to cancel" 20 78; then
      
      # Set up .ssh directory with correct permissions
      user_home=$(eval echo ~${username})
      mkdir -p ${user_home}/.ssh
      touch ${user_home}/.ssh/authorized_keys
      
      # Fix permissions
      chmod 700 ${user_home}/.ssh
      chmod 600 ${user_home}/.ssh/authorized_keys
      chown -R ${username}:${username} ${user_home}/.ssh
      
      msg_ok "SSH directory created with correct permissions for $username"
      msg_ok "SSH configuration complete - ready for keys!"
      
      echo "You can now copy your key from your local machine using:"
      echo "ssh-copy-id $username@SERVER_IP"
      echo ""
      echo "These server-side preparations will allow you to use SSH keys for login."
    else
      msg_info "SSH key setup cancelled"
    fi
  else
    msg_info "SSH key setup cancelled"
  fi
}

# Function to set up passwordless sudo for SSH users
setup_passwordless_sudo() {
  # Get list of sudo-capable users
  sudo_users=$(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' ' ')
  
  # Format for whiptail menu
  user_options=""
  item_num=1
  for user in $sudo_users; do
    user_options="$user_options $item_num $user "
    ((item_num++))
  done
  
  if [ -z "$user_options" ]; then
    msg_info "No sudo users found for passwordless configuration"
    return
  fi
  
  # Ask if user wants to configure passwordless sudo
  if whiptail --title "Passwordless Sudo" --yesno \
    "Would you like to configure passwordless sudo for SSH users?\n\nThis allows running sudo commands without entering a password.\n\nNOTE: This is most secure when SSH key authentication is enforced and password authentication is disabled." 12 78; then
    
    # Show user selection menu
    selected_user=$(whiptail --title "Passwordless Sudo" --menu \
      "Select a user to enable passwordless sudo for:" 16 60 8 $user_options 3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 && ! -z "$selected_user" ]]; then
      username=$(echo $sudo_users | tr ' ' '\n' | sed -n "${selected_user}p")
      
      # Check if user has SSH keys configured
      user_home=$(eval echo ~${username})
      if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
        ssh_key_status="SSH keys are properly configured for this user."
        key_warning=""
      else
        ssh_key_status="WARNING: No SSH keys detected for this user!"
        key_warning="\n\nEnabling passwordless sudo WITHOUT SSH key authentication is a security risk."
      fi
      
      # Ask for confirmation
      if whiptail --title "Confirm Passwordless Sudo" --yesno \
        "${ssh_key_status}${key_warning}\n\nAre you sure you want to enable passwordless sudo for ${username}?" 12 78; then
        
        # Configure passwordless sudo
        echo "${username} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-${username}-nopasswd
        chmod 440 /etc/sudoers.d/99-${username}-nopasswd
        msg_ok "Passwordless sudo enabled for ${username}"
      else
        msg_info "Passwordless sudo configuration cancelled"
      fi
    else
      msg_info "No user selected for passwordless sudo"
    fi
  else
    msg_info "Passwordless sudo configuration skipped"
  fi
}

# Firewall setup function
configure_firewall() {
  if ! command -v ufw >/dev/null; then
    msg_info "Installing UFW (Uncomplicated Firewall)..."
    apt install -y ufw
  fi
  
  # Check if UFW is already enabled
  ufw_status=$(ufw status | head -1)
  
  if whiptail --title "Firewall Configuration" --yesno "Would you like to configure the firewall (UFW)?\n\nCurrent status: $ufw_status" 10 60; then
    # Confirm the basics
    if whiptail --title "Basic Firewall Rules" --yesno "Do you want to apply the recommended basic rules?\n\n• Allow SSH (port 22)\n• Deny all other incoming connections\n• Allow all outgoing connections" 12 70; then
      # Configure basic rules
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow 22/tcp comment 'SSH'
      msg_ok "Basic firewall rules configured"
    fi
    
    # Ask about common web services
    web_services=$(whiptail --title "Common Web Services" --checklist \
      "Select web services to allow:" 10 60 2 \
      "HTTP" "Web server (port 80)" OFF \
      "HTTPS" "Secure web server (port 443)" OFF 3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 && ! -z "$web_services" ]]; then
      # Process selected services
      if [[ $web_services == *"HTTP"* ]]; then
        ufw allow 80/tcp comment 'HTTP'
        msg_ok "HTTP traffic allowed"
      fi
      
      if [[ $web_services == *"HTTPS"* ]]; then
        ufw allow 443/tcp comment 'HTTPS'
        msg_ok "HTTPS traffic allowed"
      fi
    fi
    
    # Ask about custom port
    if whiptail --title "Custom Port" --yesno "Do you want to allow any custom ports?" 8 60; then
      while true; do
        port=$(whiptail --inputbox "Enter port number to allow (1-65535):" 8 60 3>&1 1>&2 2>&3)
        
        if [[ $? -ne 0 || -z "$port" ]]; then
          break
        fi
        
        if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
          protocol=$(whiptail --title "Protocol" --menu "Select protocol:" 10 60 3 \
            "tcp" "TCP only" \
            "udp" "UDP only" \
            "both" "Both TCP and UDP" 3>&1 1>&2 2>&3)
          
          if [[ $? -eq 0 ]]; then
            description=$(whiptail --inputbox "Enter a description for this rule:" 8 60 "Custom port" 3>&1 1>&2 2>&3)
            
            if [[ $protocol == "tcp" ]]; then
              ufw allow $port/tcp comment "$description"
              msg_ok "Port $port/tcp allowed: $description"
            elif [[ $protocol == "udp" ]]; then
              ufw allow $port/udp comment "$description"
              msg_ok "Port $port/udp allowed: $description"
            else
              ufw allow $port comment "$description"
              msg_ok "Port $port (tcp & udp) allowed: $description"
            fi
          fi
        else
          whiptail --title "Invalid Port" --msgbox "Please enter a valid port number between 1 and 65535." 8 70
        fi
        
        if ! whiptail --title "Additional Ports" --yesno "Do you want to allow another port?" 8 60; then
          break
        fi
      done
    fi
    
    # VPN subnet allowance
    vpn_subnet=""
    if [ -f /tmp/vpn_subnet ]; then
      vpn_subnet=$(cat /tmp/vpn_subnet)
    fi
    
    if [[ ! -z "$vpn_subnet" ]]; then
      if whiptail --title "VPN Subnet" --yesno "VPN subnet detected: $vpn_subnet\n\nDo you want to allow all traffic from this subnet?" 10 70; then
        ufw allow from $vpn_subnet comment "VPN subnet"
        msg_ok "Traffic from VPN subnet $vpn_subnet allowed"
      fi
    fi
    
    # Enable UFW if it's not already enabled
    if [[ "$ufw_status" != *"active"* ]]; then
      if whiptail --title "Enable Firewall" --yesno "Do you want to enable the firewall now with the configured rules?" 8 60; then
        echo "y" | ufw enable
        msg_ok "Firewall enabled successfully"
      else
        msg_info "Firewall configured but not enabled"
      fi
    else
      if whiptail --title "Reload Firewall" --yesno "Firewall is already active. Do you want to reload the configuration?" 8 60; then
        ufw reload
        msg_ok "Firewall configuration reloaded"
      fi
    fi
    
    # Show UFW rules summary
    ufw_rules=$(ufw status verbose)
    whiptail --title "Firewall Rules Summary" --scrolltext --msgbox "Current firewall configuration:\n\n$ufw_rules" 20 78
  else
    msg_info "Firewall configuration skipped"
  fi
}

# Setup Fail2Ban function
setup_fail2ban() {
  if whiptail --title "Fail2Ban Installation" --yesno "Would you like to install and configure Fail2Ban?\n\nFail2Ban is a tool that helps protect your server against brute-force attacks." 10 70; then
    msg_info "Installing Fail2Ban..."
    apt install -y fail2ban
    
    # Create a local configuration
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Configure Fail2Ban settings
    ban_time=$(whiptail --inputbox "Enter ban time in seconds (default: 600):" 8 60 "600" 3>&1 1>&2 2>&3)
    find_time=$(whiptail --inputbox "Enter find time in seconds (default: 600):" 8 60 "600" 3>&1 1>&2 2>&3)
    max_retry=$(whiptail --inputbox "Enter max retry attempts (default: 5):" 8 60 "5" 3>&1 1>&2 2>&3)
    
    # Apply settings
    if [[ $? -eq 0 ]]; then
      # Get additional IP whitelist
      additional_ips=$(whiptail --inputbox "Enter additional IPs to whitelist (space-separated):" 8 70 "" 3>&1 1>&2 2>&3)
      
      # Always include localhost
      whitelist_ips="127.0.0.1 ::1"
      if [[ ! -z "$additional_ips" ]]; then
        whitelist_ips="$whitelist_ips $additional_ips"
      fi
      
      # Add VPN subnet if available
      vpn_subnet=""
      if [ -f /tmp/vpn_subnet ]; then
        vpn_subnet=$(cat /tmp/vpn_subnet)
        whitelist_ips="$whitelist_ips $vpn_subnet"
      fi
      
      # Create custom config
      cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for $ban_time seconds
bantime = $ban_time
# Find time window
findtime = $find_time
# Allow $max_retry retries
maxretry = $max_retry
# Ignore these IPs
ignoreip = $whitelist_ips

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = $max_retry
EOF
      
      # Enable and start Fail2Ban
      systemctl enable fail2ban
      systemctl restart fail2ban
      
      msg_ok "Fail2Ban installed and configured"
      
      # Show status
      fail2ban_status=$(fail2ban-client status)
      jails=$(fail2ban-client status | grep "Jail list" | sed 's/^.*: //')
      
      jail_status=""
      for jail in $jails; do
        jail_info=$(fail2ban-client status $jail)
        jail_status="${jail_status}\n\n[$jail]\n${jail_info}"
      done
      
      whiptail --title "Fail2Ban Status" --msgbox "Fail2Ban has been installed and configured with:\n\nBan time: $ban_time seconds\nFind time: $find_time seconds\nMax retries: $max_retry\nWhitelisted IPs: $whitelist_ips\n$jail_status" 20 78
    else
      msg_info "Using default Fail2Ban configuration"
      systemctl enable fail2ban
      systemctl restart fail2ban
    fi
  else
    msg_info "Fail2Ban installation skipped"
  fi
}

# Setup VPN function
setup_vpn() {
  vpn_choice=$(whiptail --title "VPN Setup" --menu \
    "Would you like to set up a VPN for secure remote access?" 15 60 3 \
    "1" "Tailscale (easy to use, managed service)" \
    "2" "Netbird (open-source, self-hostable)" \
    "3" "Skip VPN setup" 3>&1 1>&2 2>&3)
  
  case $vpn_choice in
    1)
      setup_tailscale
      ;;
    2)
      setup_netbird
      ;;
    3)
      msg_info "VPN setup skipped"
      ;;
    *)
      msg_info "VPN setup skipped"
      ;;
  esac
}

# Setup Tailscale function
setup_tailscale() {
  msg_info "Installing Tailscale..."
  
  # Add Tailscale repository and install
  curl -fsSL https://tailscale.com/install.sh | sh
  
  if [[ $? -eq 0 ]]; then
    msg_ok "Tailscale installed successfully"
    
    auth_key=""
    if whiptail --title "Tailscale Authentication" --yesno "Do you have a Tailscale auth key?\n\nIf not, select 'No' and you'll be given a URL to authenticate manually." 10 70; then
      auth_key=$(whiptail --inputbox "Enter your Tailscale auth key:" 8 70 3>&1 1>&2 2>&3)
    fi
    
    if [[ ! -z "$auth_key" ]]; then
      tailscale up --authkey="$auth_key"
      msg_ok "Tailscale configured with auth key"
    else
      # Start Tailscale without auth key
      tailscale up
      msg_info "Tailscale started. Please authenticate using the URL above."
      read -p "Press Enter once you've authenticated... "
    fi
    
    # Get Tailscale IP and subnet
    tailscale_ip=$(tailscale ip)
    tailscale_subnet="100.64.0.0/10"  # Default Tailscale subnet
    
    # Save subnet for firewall rules
    echo "$tailscale_subnet" > /tmp/vpn_subnet
    
    whiptail --title "Tailscale Configured" --msgbox "Tailscale has been successfully configured.\n\nYour Tailscale IP: $tailscale_ip\nTailscale subnet: $tailscale_subnet\n\nYou can now connect to this server securely via the Tailscale network." 12 70
  else
    msg_error "Tailscale installation failed"
  fi
}

# Setup Netbird function
setup_netbird() {
  msg_info "Installing Netbird..."
  
  # Add Netbird repository and install
  curl -fsSL https://pkgs.netbird.io/install.sh | sh
  
  if [[ $? -eq 0 ]]; then
    msg_ok "Netbird installed successfully"
    
    setup_key=$(whiptail --inputbox "Enter your Netbird setup key:" 8 70 3>&1 1>&2 2>&3)
    
    if [[ ! -z "$setup_key" ]]; then
      netbird up --setup-key "$setup_key"
      msg_ok "Netbird configured with setup key"
      
      # Get Netbird IP and subnet
      netbird_ip=$(ip addr show netbird0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "Unknown")
      netbird_subnet=$(whiptail --inputbox "Enter your Netbird IP range (e.g., 100.92.0.0/16):" 8 70 "100.92.0.0/16" 3>&1 1>&2 2>&3)
      
      # Save subnet for firewall rules
      echo "$netbird_subnet" > /tmp/vpn_subnet
      
      whiptail --title "Netbird Configured" --msgbox "Netbird has been successfully configured.\n\nYour Netbird IP: $netbird_ip\nNetbird subnet: $netbird_subnet\n\nYou can now connect to this server securely via the Netbird network." 12 70
    else
      msg_error "Netbird setup key not provided"
    fi
  else
    msg_error "Netbird installation failed"
  fi
}

# Function for additional system measures
configure_additional_measures() {
