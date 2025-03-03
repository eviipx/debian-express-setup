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
  msg_info "Configuring additional system measures..."
  
  # Automatic security updates
  setup_auto_updates
  
  # System optimization
  system_optimization
  
  # Disable unused services
  disable_unused_services
  
  msg_ok "Additional system measures configured"
}

# Function to set up automatic security updates
setup_auto_updates() {
  if whiptail --title "Automatic Updates" --yesno "Would you like to configure automatic security updates?" 8 70; then
    msg_info "Setting up unattended-upgrades..."
    
    # Install required packages
    apt install -y unattended-upgrades apt-listchanges
    
    # Configure automatic updates
    cat > /etc/apt/apt.conf.d/20auto-upgrades << EOF
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
    
    # Ask about automatic reboot if needed
    if whiptail --title "Automatic Reboot" --yesno "Would you like to enable automatic reboot when necessary?\n\nThis will reboot the system automatically if an update requires it." 10 70; then
      sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
      
      # Ask about reboot time
      reboot_time=$(whiptail --inputbox "Enter preferred reboot time (24-hour format, e.g., 02:00):" 8 70 "02:00" 3>&1 1>&2 2>&3)
      if [[ $? -eq 0 && ! -z "$reboot_time" ]]; then
        sed -i "s|//Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";|Unattended-Upgrade::Automatic-Reboot-Time \"$reboot_time\";|" /etc/apt/apt.conf.d/50unattended-upgrades
      fi
      
      msg_ok "Automatic reboot configured for $reboot_time"
    else
      sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "false";|' /etc/apt/apt.conf.d/50unattended-upgrades
      msg_info "Automatic reboot not enabled"
    fi
    
    # Restart unattended-upgrades service
    systemctl restart unattended-upgrades
    
    msg_ok "Automatic security updates configured successfully"
  else
    msg_info "Automatic security updates not configured"
  fi
}

# Function for system optimization
system_optimization() {
  if whiptail --title "System Optimization" --yesno "Would you like to apply system optimizations?" 8 70; then
    
    # Setup nohang to prevent system freezes
    if whiptail --title "Nohang Installation" --yesno "Would you like to install nohang?\n\nNohang is a daemon that prevents system freezes caused by out-of-memory conditions." 10 70; then
      msg_info "Installing nohang..."
      
      # Add repository and install nohang
      add-apt-repository ppa:oibaf/test -y
      apt update
      apt install -y nohang
      
      # Enable and start nohang services
      systemctl enable --now nohang-desktop.service
      
      msg_ok "Nohang installed and configured successfully"
    else
      msg_info "Nohang installation skipped"
    fi
    
    # Setup swap file
    setup_swap
    
    # I/O scheduler optimization
    if whiptail --title "I/O Scheduler" --yesno "Would you like to optimize the I/O scheduler?\n\nThis can improve disk performance, especially for SSDs." 10 70; then
      # Check for SSD
      has_ssd=false
      for drive in $(lsblk -d -o name | tail -n +2); do
        if [ -d "/sys/block/$drive/queue/rotational" ]; then
          if [ "$(cat /sys/block/$drive/queue/rotational)" -eq 0 ]; then
            has_ssd=true
          fi
        fi
      done
      
      if $has_ssd; then
        # Optimize for SSD
        cat > /etc/udev/rules.d/60-scheduler.rules << EOF
# Set scheduler for SSD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="deadline"
# Set scheduler for HDD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
EOF
        msg_ok "I/O scheduler optimized for SSDs and HDDs"
      else
        # Optimize for HDD only
        cat > /etc/udev/rules.d/60-scheduler.rules << EOF
# Set scheduler for HDD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/scheduler}="bfq"
EOF
        msg_ok "I/O scheduler optimized for HDDs"
      fi
    fi
    
    # System kernel parameters optimization
    if whiptail --title "Kernel Parameters" --yesno "Would you like to optimize kernel parameters?\n\nThis can improve system performance and network responsiveness." 10 70; then
      cat > /etc/sysctl.d/99-performance.conf << EOF
# Increase file system performance
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# Improve network performance
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1

# Improve overall system responsiveness
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF
      
      # Apply changes
      sysctl -p /etc/sysctl.d/99-performance.conf
      
      msg_ok "Kernel parameters optimized"
    fi
    
    msg_ok "System optimization completed"
  else
    msg_info "System optimization skipped"
  fi
}

# Swap file setup function based on RAM
setup_swap() {
  # Check if swap exists
  swap_exists=0
  swap_size=0
  if [ "$(swapon --show | wc -l)" -gt 0 ]; then
    swap_exists=1
    swap_size=$(free -m | grep Swap | awk '{print $2}')
  fi
  
  # Get system RAM
  ram_size=$(free -m | grep Mem | awk '{print $2}')
  
  # Determine recommended swap size based on RAM
  if [ $ram_size -lt 2048 ]; then
    # Less than 2GB RAM: Swap = 2x RAM
    recommended_swap=$((ram_size * 2))
  elif [ $ram_size -le 8192 ]; then
    # 2-8GB RAM: Swap = 1x RAM
    recommended_swap=$ram_size
  elif [ $ram_size -le 16384 ]; then
    # 8-16GB RAM: Swap = 0.5x RAM (minimum 4GB)
    recommended_swap=$((ram_size / 2))
    if [ $recommended_swap -lt 4096 ]; then
      recommended_swap=4096
    fi
  else
    # >16GB RAM: 4GB swap
    recommended_swap=4096
  fi
  
  # Display swap information
  if [ $swap_exists -eq 1 ]; then
    swap_action=$(whiptail --title "Swap Configuration" --menu "Current swap: ${swap_size}MB, RAM: ${ram_size}MB\nRecommended swap: ${recommended_swap}MB\n\nWhat would you like to do?" 16 70 3 \
      "KEEP" "Keep current swap configuration" \
      "RESIZE" "Resize swap to recommended size (${recommended_swap}MB)" \
      "CUSTOM" "Set a custom swap size" 3>&1 1>&2 2>&3)
  else
    swap_action=$(whiptail --title "Swap Configuration" --menu "No swap detected, RAM: ${ram_size}MB\nRecommended swap: ${recommended_swap}MB\n\nWhat would you like to do?" 16 70 3 \
      "CREATE" "Create swap with recommended size (${recommended_swap}MB)" \
      "CUSTOM" "Create swap with custom size" \
      "NONE" "Do not create swap" 3>&1 1>&2 2>&3)
  fi
  
  case "$swap_action" in
    KEEP)
      msg_info "Keeping current swap configuration"
      ;;
    RESIZE)
      # Turn off existing swap
      swapoff -a
      # Resize the swap file
      create_swap_file "${recommended_swap}"
      ;;
    CREATE)
      create_swap_file "${recommended_swap}"
      ;;
    CUSTOM)
      custom_size=$(whiptail --inputbox "Enter desired swap size in MB:" 8 60 "${recommended_swap}" 3>&1 1>&2 2>&3)
      if [ $? -eq 0 ] && [ ! -z "$custom_size" ]; then
        if [ $swap_exists -eq 1 ]; then
          swapoff -a
        fi
        create_swap_file "${custom_size}"
      else
        msg_info "Swap configuration unchanged"
      fi
      ;;
    NONE)
      msg_info "No swap will be created"
      ;;
    *)
      msg_info "Swap configuration unchanged"
      ;;
  esac
}

# Function to create and configure swap file
create_swap_file() {
  local size_mb=$1
  
  msg_info "Creating ${size_mb}MB swap file..."
  
  # Remove old swap file if it exists
  if [ -f /swapfile ]; then
    rm -f /swapfile
  fi
  
  # Create new swap file
  fallocate -l ${size_mb}M /swapfile
  chmod 600 /swapfile
  mkswap /swapfile
  swapon /swapfile
  
  # Add to fstab if not already there
  if ! grep -q "^/swapfile none swap" /etc/fstab; then
    echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
  
  # Configure swappiness and cache pressure
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-swappiness.conf
  sysctl -p /etc/sysctl.d/99-swappiness.conf
  
  msg_ok "Swap file created and configured (${size_mb}MB)"
}

# Function to disable unused services
disable_unused_services() {
  if whiptail --title "Disable Unused Services" --yesno "Would you like to disable commonly unused services to save resources?" 8 70; then
    # Track services we've configured
    configured_services=""
    if [ -f /tmp/configured_services ]; then
      configured_services=$(cat /tmp/configured_services)
    fi
    
    # Get list of services that can be safely disabled
    services=$(systemctl list-unit-files --type=service --state=enabled --no-pager | grep -v "ssh\|network\|systemd\|dbus\|$configured_services" | awk '{print $1}' | grep "\.service$" | sed 's/\.service//g')
    
    # Format services for checklist - all pre-selected by default
    service_options=""
    for svc in $services; do
      desc=$(systemctl show -p Description --value $svc 2>/dev/null || echo "No description available")
      service_options="$service_options $svc \"$desc\" ON "  # Notice ON instead of OFF
    done
    
    if [ -z "$service_options" ]; then
      whiptail --title "No Services Available" --msgbox "No non-essential services were found that can be disabled." 8 70
    else
      disabled_services=$(whiptail --title "Select Services to Disable" --checklist \
        "All non-essential services are selected by default.\nDeselect any services you want to keep:" 20 78 10 $service_options 3>&1 1>&2 2>&3)
      
      if [[ $? -eq 0 && ! -z "$disabled_services" ]]; then
        for svc in $(echo $disabled_services | tr -d '"'); do
          systemctl stop $svc
          systemctl disable $svc
          msg_ok "Service $svc stopped and disabled"
        done
        
        msg_ok "Selected services have been disabled"
      else
        msg_info "No services were selected to disable"
      fi
    fi
  else
    msg_info "Service disabling skipped"
  fi
}

# Function to set up monitoring and management tools
setup_monitoring_benchmarking() {
  msg_info "Setting up monitor and benchmark tools..."
  
  # Server Management Panel
  setup_management_panel
  
  # Monitoring tools
  setup_monitor_benchmark_tools
  
  # Logwatch configuration
  setup_logwatch
  
  # Backup installation (simplified)
  setup_backup_tool
  
  msg_ok "Monitor and benchmark tools configuration completed"
}

# Function to set up server management panel
setup_management_panel() {
  panel_choice=$(whiptail --title "Server Management Panel" --menu \
    "Would you like to install a server management panel?" 15 60 3 \
    "1" "Webmin (feature-rich, traditional)" \
    "2" "Easy Panel (modern, container-focused)" \
    "3" "Skip panel installation" 3>&1 1>&2 2>&3)
  
  case $panel_choice in
    1)
      setup_webmin
      ;;
    2)
      setup_easy_panel
      ;;
    3)
      msg_info "Server management panel installation skipped"
      ;;
    *)
      msg_info "Server management panel installation skipped"
      ;;
  esac
}

# Function to set up Webmin
setup_webmin() {
  msg_info "Installing Webmin..."
  
  # Add Webmin repository and install
  curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
  sh setup-repos.sh
  apt install -y webmin
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    
    # Check if firewall is enabled and add rule if needed
    ufw_status=$(ufw status | head -1)
    if [[ "$ufw_status" == *"active"* ]]; then
      msg_info "Firewall is active. Adding rule for Webmin..."
      ufw allow 10000/tcp comment 'Webmin'
      msg_ok "Firewall rule added for Webmin (port 10000)"
    fi
    
    msg_ok "Webmin installed successfully"
    echo "webmin" >> /tmp/configured_services
    
    # Save info for summary
    mkdir -p /tmp/debian-express-setup
    cat > /tmp/debian-express-setup/webmin-info.txt << EOF
Webmin has been installed successfully.

You can access the Webmin interface at:
https://$server_ip:10000

Default login: Current system username/password
EOF

  else
    msg_error "Webmin installation failed"
  fi
}

# Function to set up Easy Panel
setup_easy_panel() {
  msg_info "Installing Easy Panel..."
  
  # Check if Docker is installed
  if ! command -v docker >/dev/null; then
    msg_info "Docker is required for Easy Panel. Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    msg_ok "Docker installed"
  fi
  
  # Install Easy Panel
  curl -fsSL https://get.easypanel.io | sh
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    
    # Check if firewall is enabled and add rule if needed
    ufw_status=$(ufw status | head -1)
    if [[ "$ufw_status" == *"active"* ]]; then
      msg_info "Firewall is active. Adding rule for Easy Panel..."
      ufw allow 3000/tcp comment 'Easy Panel'
      msg_ok "Firewall rule added for Easy Panel (port 3000)"
    fi
    
    msg_ok "Easy Panel installed successfully"
    echo "easypanel" >> /tmp/configured_services
    
    # Save info for summary
    mkdir -p /tmp/debian-express-setup
    cat > /tmp/debian-express-setup/easypanel-info.txt << EOF
Easy Panel has been installed successfully.

You can access the Easy Panel interface at:
http://$server_ip:3000

Follow the on-screen instructions to complete setup.
EOF
  else
    msg_error "Easy Panel installation failed"
  fi
}

# Function to set up monitoring tools
setup_monitor_benchmark_tools() {
  if whiptail --title "Monitor and Benchmark Tools" --yesno "Would you like to install system monitor and benchmark tools?" 8 70; then
    monitoring_tools=$(whiptail --title "Monitor and Benchmark Tools" --checklist \
      "Select tools to install:" 15 60 3 \
      "btop" "Modern resource monitor" ON \
      "speedtest-cli" "Internet speed test" ON \
      "fastfetch" "System information display" ON 3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 && ! -z "$monitoring_tools" ]]; then
      # Install selected tools
      if [[ $monitoring_tools == *"btop"* ]]; then
        msg_info "Installing btop..."
        apt install -y btop
        msg_ok "btop installed"
      fi
      
      if [[ $monitoring_tools == *"speedtest-cli"* ]]; then
        msg_info "Installing speedtest-cli..."
        apt install -y speedtest-cli
        msg_ok "speedtest-cli installed"
      fi
      
      if [[ $monitoring_tools == *"fastfetch"* ]]; then
        msg_info "Installing fastfetch..."
        add-apt-repository ppa:zhangsongcui3371/fastfetch -y
        apt update
        apt install -y fastfetch
        msg_ok "fastfetch installed"
      fi
      
      msg_ok "Monitoring tools installed successfully"
    else
      msg_info "No monitoring tools selected"
    fi
  else
    msg_info "Monitoring tools installation skipped"
  fi
}

# Function to set up Logwatch with best practices
setup_logwatch() {
  if whiptail --title "Logwatch Setup" --yesno "Would you like to install and configure Logwatch for log monitoring?\n\nLogwatch provides daily system log analysis and reports." 10 70; then
    msg_info "Installing Logwatch..."
    apt install -y logwatch mailutils
    
    # Get admin email
    admin_email=$(whiptail --inputbox "Enter email address for system reports:" 8 70 "admin@$(hostname -f)" 3>&1 1>&2 2>&3)
    
    if [[ $? -eq 0 && ! -z "$admin_email" ]]; then
      # Create optimized configuration
      mkdir -p /etc/logwatch/conf
      cat > /etc/logwatch/conf/logwatch.conf << EOF
# Logwatch configuration - Best practices
Output = mail
Format = html
MailTo = $admin_email
MailFrom = logwatch@$(hostname -f)
Range = yesterday
Detail = Medium
Service = All
mailer = "/usr/bin/mail -s 'Logwatch report for $(hostname)'"
# Ignore less important services to reduce noise
Service = "-zz-network"
Service = "-zz-sys"
Service = "-eximstats"
EOF
      
      # Set up a daily cron job with random execution time to avoid server load spikes
      echo "$(($RANDOM % 60)) $(($RANDOM % 5)) * * * /usr/sbin/logwatch" > /etc/cron.d/logwatch
      chmod 644 /etc/cron.d/logwatch
      
      msg_ok "Logwatch installed and configured to send reports to $admin_email"
      
      # Save info for summary
      mkdir -p /tmp/debian-express-setup
      cat > /tmp/debian-express-setup/logwatch-info.txt << EOF
Logwatch has been installed and configured.

Daily reports will be sent to: $admin_email
Report frequency: Daily (previous day's logs)
Report format: HTML
Detail level: Medium
EOF
    else
      # Default configuration if no email provided
      msg_info "Using default Logwatch configuration"
    fi
  else
    msg_info "Logwatch setup skipped"
  fi
}

# Simplified function to just install Restic backup tool
setup_backup_tool() {
  if whiptail --title "Backup Tool" --yesno "Would you like to install Restic backup tool?\n\nRestic is a modern, fast and secure backup program." 10 70; then
    msg_info "Installing Restic backup tool..."
    apt install -y restic
    
    if [[ $? -eq 0 ]]; then
      msg_ok "Restic backup tool installed successfully"
      
      # Save information for final summary
      mkdir -p /tmp/debian-express-setup
      cat > /tmp/debian-express-setup/restic-info.txt << EOF
Restic has been installed successfully.

To configure backups later, you can use these commands:

• Initialize a repository:
  restic init --repo /path/to/repo

• Create a backup:
  restic -r /path/to/repo backup /path/to/files

• List snapshots:
  restic -r /path/to/repo snapshots

• Restore files:
  restic -r /path/to/repo restore latest --target /path/to/restore

See 'man restic' for more details
EOF
    else
      msg_error "Restic backup tool installation failed"
    fi
  else
    msg_info "Backup tool installation skipped"
  fi
}

# Function to set up container management
setup_containers() {
  msg_info "Setting up container management..."
  
  # Docker installation
  setup_docker
  
  # Dockge (container manager) installation
  setup_dockge
  
  msg_ok "Container management setup completed"
}

# Function to set up Docker
setup_docker() {
  if whiptail --title "Docker Installation" --yesno "Would you like to install Docker?\n\nDocker allows you to run applications in containers." 10 70; then
    msg_info "Installing Docker..."
    
    # Install Docker using the official script
    curl -fsSL https://get.docker.com | sh
    
    if [[ $? -eq 0 ]]; then
      # Create docker group and add current non-root user if exists
      groupadd -f docker
      
      # Get list of non-system users
      users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
      
      # Format for whiptail checklist
      user_options=""
      for user in $users; do
        user_options="$user_options $user $user OFF "
      done
      
      if [[ ! -z "$user_options" ]]; then
        selected_users=$(whiptail --title "Docker Access" --checklist \
          "Select users to add to the docker group (allows running Docker without sudo):" 15 70 8 $user_options 3>&1 1>&2 2>&3)
        
        if [[ $? -eq 0 && ! -z "$selected_users" ]]; then
          for user in $(echo $selected_users | tr -d '"'); do
            usermod -aG docker $user
            msg_ok "Added user $user to the docker group"
          done
        fi
      fi
      
      # Enable and start Docker service
      systemctl enable --now docker
      
      # Install Docker Compose plugin
      apt install -y docker-compose-plugin
      
      msg_ok "Docker installed successfully"
      echo "docker" >> /tmp/configured_services
      
      # Save Docker info for summary
      mkdir -p /tmp/debian-express-setup
      echo "Docker has been installed successfully with Docker Compose plugin." > /tmp/debian-express-setup/docker-info.txt
      echo "Users added to docker group can run Docker commands without sudo." >> /tmp/debian-express-setup/docker-info.txt
      echo "Remember that users need to log out and back in for group changes to take effect." >> /tmp/debian-express-setup/docker-info.txt
    else
      msg_error "Docker installation failed"
    fi
  else
    msg_info "Docker installation skipped"
  fi
}

# Function to set up Dockge (container manager)
setup_dockge() {
  # Only offer Dockge if Docker is installed
  if command -v docker >/dev/null; then
    if whiptail --title "Dockge Installation" --yesno "Would you like to install Dockge container manager?\n\nDockge is a modern UI for managing Docker Compose stacks." 10 70; then
      msg_info "Installing Dockge..."
      
      # Create directory structure
      mkdir -p /opt/stacks/dockge/data
      cd /opt/stacks/dockge
      
      # Download docker-compose.yml
      curl -fsSL https://github.com/louislam/dockge/releases/latest/download/docker-compose.yml -o docker-compose.yml
      
      # Set up admin password
      admin_password=$(whiptail --passwordbox "Create a new admin password for Dockge:" 8 70 3>&1 1>&2 2>&3)
      if [[ $? -eq 0 && ! -z "$admin_password" ]]; then
        # Create .env file with password
        echo "DOCKGE_ADMIN_PASSWORD=$admin_password" > .env
      else
        # Generate random password
        random_password=$(openssl rand -base64 12)
        echo "DOCKGE_ADMIN_PASSWORD=$random_password" > .env
        msg_info "Generated random password: $random_password"
      fi
      
      # Start Dockge
      docker compose up -d
      
      if [[ $? -eq 0 ]]; then
        # Get server IP
        server_ip=$(hostname -I | awk '{print $1}')
        
        # Check if firewall is enabled and add rule if needed
        ufw_status=$(ufw status | head -1)
        if [[ "$ufw_status" == *"active"* ]]; then
          msg_info "Firewall is active. Adding rule for Dockge..."
          ufw allow 5001/tcp comment 'Dockge'
          msg_ok "Firewall rule added for Dockge (port 5001)"
        fi
        
        msg_ok "Dockge installed successfully"
        echo "dockge" >> /tmp/configured_services
        
        # Save Dockge info for summary
        mkdir -p /tmp/debian-express-setup
        dockge_password=$(cat .env | grep DOCKGE_ADMIN_PASSWORD | cut -d= -f2)
        cat > /tmp/debian-express-setup/dockge-info.txt << EOF
Dockge container manager has been installed successfully.

Access URL: http://$server_ip:5001
Username: admin
Password: $dockge_password

Dockge allows you to easily manage Docker Compose stacks with a modern web interface.
EOF
      else
        msg_error "Dockge installation failed"
      fi
    else
      msg_info "Dockge installation skipped"
    fi
  else
    msg_info "Docker not installed. Skipping Dockge installation."
  fi
}

# Function to clean up and complete setup
finalize_setup() {
  msg_info "Finalizing setup..."
  
  # System cleanup
  apt autoremove -y
  apt clean
  
  # Generate and display the final summary
  display_final_summary
  
  msg_ok "Debian Express Setup completed successfully!"
  echo
  echo "Your server has been configured according to your preferences."
  echo "Please review the summary information provided."
  echo
  echo "For security reasons, you should reboot your server to apply all changes."
  echo
  read -p "Would you like to reboot now? (y/N): " reboot_choice
  if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
    echo "Rebooting system in 5 seconds..."
    sleep 5
    reboot
  else
    echo "Please remember to reboot your system manually later."
  fi
}

# Function to display final setup summary
display_final_summary() {
  # Get server IP
  server_ip=$(hostname -I | awk '{print $1}')
  
  # Build summary information
  summary="=== Debian Express Setup Summary ===\n\n"
  summary+="System Information:\n"
  summary+="• Hostname: $(hostname)\n"
  summary+="• IP Address: $server_ip\n"
  summary+="• OS: $(lsb_release -ds)\n\n"
  
  # Check what was installed and configured
  summary+="Security Configuration:\n"
  
  # SSH status
  if [ -f /etc/ssh/sshd_config.d/50-security.conf ]; then
    summary+="• SSH: Hardened configuration applied\n"
    if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config.d/50-security.conf; then
      summary+="  - Password authentication: Disabled\n"
    else
      summary+="  - Password authentication: Enabled\n"
    fi
    if grep -q "PermitRootLogin no" /etc/ssh/sshd_config.d/50-security.conf; then
      summary+="  - Root login: Disabled\n"
    fi
  else
    summary+="• SSH: Standard configuration\n"
  fi
  
  # Firewall status
  ufw_status=$(ufw status | head -1)
  if [[ "$ufw_status" == *"active"* ]]; then
    summary+="• Firewall (UFW): Enabled\n
    # Get firewall rules and format them
    ufw_rules=$(ufw status | grep -v "Status:" | sed 's/^/    /')
    summary+="  - Rules:\n$ufw_rules\n"
  else
    summary+="• Firewall (UFW): Disabled\n"
  fi
  
  # Fail2Ban status
  if systemctl is-active --quiet fail2ban; then
    summary+="• Fail2Ban: Active\n"
  else
    summary+="• Fail2Ban: Not configured\n"
  fi
  
  # Automatic updates
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    summary+="• Automatic updates: Configured\n"
  else
    summary+="• Automatic updates: Not configured\n"
  fi
  
  # VPN status
  if systemctl is-active --quiet tailscale; then
    summary+="• VPN: Tailscale active (IP: $(tailscale ip))\n"
  elif systemctl is-active --quiet netbird; then
    summary+="• VPN: Netbird active\n"
  else
    summary+="• VPN: Not configured\n"
  fi
  
  # System optimization status
  if [ -f /etc/sysctl.d/99-performance.conf ]; then
    summary+="• System optimizations: Applied\n"
  else
    summary+="• System optimizations: Not applied\n"
  fi
  
  # Swap status
  swap_size=$(free -h | grep Swap | awk '{print $2}')
  summary+="• Swap: $swap_size\n\n"
  
  # Installed services
  summary+="Installed Services:\n"
  
  # Management panel
  if systemctl is-active --quiet webmin; then
    summary+="• Webmin: Installed and running\n"
    summary+="  - URL: https://$server_ip:10000\n"
  elif [ -d /opt/easypanel ]; then
    summary+="• Easy Panel: Installed and running\n"
    summary+="  - URL: http://$server_ip:3000\n"
  else
    summary+="• Management panel: Not installed\n"
  fi
  
  # Docker status
  if command -v docker >/dev/null; then
    summary+="• Docker: Installed ($(docker --version | cut -d' ' -f3 | tr -d ','))\n"
    
    # Check if Dockge is installed
    if docker ps | grep -q dockge; then
      summary+="• Dockge container manager: Installed\n"
      summary+="  - URL: http://$server_ip:5001\n"
    else
      summary+="• Dockge container manager: Not installed\n"
    fi
  else
    summary+="• Docker: Not installed\n"
  fi
  
  # Monitoring tools
  tools=""
  if command -v btop >/dev/null; then
    tools+="btop "
  fi
  if command -v speedtest-cli >/dev/null; then
    tools+="speedtest-cli "
  fi
  if command -v fastfetch >/dev/null; then
    tools+="fastfetch "
  fi
  
  if [ ! -z "$tools" ]; then
    summary+="• Monitor and benchmark tools: $tools\n"
  else
    summary+="• Monitor and benchmark tools: None installed\n"
  fi
  
  # Logwatch status
  if [ -f /etc/logwatch/conf/logwatch.conf ]; then
    admin_email=$(grep "MailTo" /etc/logwatch/conf/logwatch.conf | cut -d' ' -f3)
    summary+="• Logwatch: Configured (Reports to: $admin_email)\n"
  else
    summary+="• Logwatch: Not configured\n"
  fi
  
  # Restic status
  if command -v restic >/dev/null; then
    summary+="• Restic backup tool: Installed\n"
  else
    summary+="• Restic backup tool: Not installed\n"
  fi
  
  # Add tool-specific information if available
  summary+="\n=== Additional Information ===\n\n"
  
  # Add Restic info if installed
  if command -v restic >/dev/null && [ -f /tmp/debian-express-setup/restic-info.txt ]; then
    summary+="Restic Backup Tool Usage:\n"
    summary+=$(cat /tmp/debian-express-setup/restic-info.txt)
    summary+="\n\n"
  fi
  
  # Add Docker info if installed
  if command -v docker >/dev/null && [ -f /tmp/debian-express-setup/docker-info.txt ]; then
    summary+="Docker Information:\n"
    summary+=$(cat /tmp/debian-express-setup/docker-info.txt)
    summary+="\n\n"
  fi
  
  # Add Dockge info if installed
  if docker ps 2>/dev/null | grep -q dockge && [ -f /tmp/debian-express-setup/dockge-info.txt ]; then
    summary+="Dockge Information:\n"
    summary+=$(cat /tmp/debian-express-setup/dockge-info.txt)
    summary+="\n\n"
  fi
  
  # Add Webmin info if installed
  if systemctl is-active --quiet webmin && [ -f /tmp/debian-express-setup/webmin-info.txt ]; then
    summary+="Webmin Information:\n"
    summary+=$(cat /tmp/debian-express-setup/webmin-info.txt)
    summary+="\n\n"
  fi
  
  # Add Easy Panel info if installed
  if [ -d /opt/easypanel ] && [ -f /tmp/debian-express-setup/easypanel-info.txt ]; then
    summary+="Easy Panel Information:\n"
    summary+=$(cat /tmp/debian-express-setup/easypanel-info.txt)
    summary+="\n\n"
  fi
  
  # Add Logwatch info if configured
  if [ -f /etc/logwatch/conf/logwatch.conf ] && [ -f /tmp/debian-express-setup/logwatch-info.txt ]; then
    summary+="Logwatch Information:\n"
    summary+=$(cat /tmp/debian-express-setup/logwatch-info.txt)
    summary+="\n\n"
  fi
  
  # Display final summary
  whiptail --title "Setup Complete" --scrolltext --msgbox "$summary" 24 78
  
  # Ask if user wants to save the summary to a file
  if whiptail --title "Save Summary" --yesno "Would you like to save this summary to a file?" 8 60; then
    summary_file="/root/debian-express-setup-summary.txt"
    echo -e "$summary" > "$summary_file"
    chmod 600 "$summary_file"
    msg_ok "Summary saved to $summary_file"
  fi
  
  # Clean up temporary files
  rm -rf /tmp/debian-express-setup
}

# Main function to orchestrate the setup process
main() {
  # Check for root privileges
  if [[ "$EUID" -ne 0 ]]; then
    echo "This script must be run as root"
    exit 1
  fi
  
  # Display welcome banner
  clear
  cat <<"EOF"
 ____       _     _                _____                              
|  _ \  ___| |__ (_) __ _ _ __   | ____|_  ___ __  _ __ ___  ___ ___ 
| | | |/ _ \ '_ \| |/ _` | '_ \  |  _| \ \/ / '_ \| '__/ _ \/ __/ __|
| |_| |  __/ |_) | | (_| | | | | | |___ >  <| |_) | | |  __/\__ \__ \
|____/ \___|_.__/|_|\__,_|_| |_| |_____/_/\_\ .__/|_|  \___||___/___/
                                            |_|                      
  ____       _               
 / ___|  ___| |_ _   _ _ __  
 \___ \ / _ \ __| | | | '_ \ 
  ___) |  __/ |_| |_| | |_) |
 |____/ \___|\__|\__,_| .__/ 
                      |_|    
EOF

  echo -e "\n${BL}Welcome to Debian Express Setup!${CL}\n"
  echo -e "This tool will help you quickly configure and secure your Debian-based server.\n"
  
  # Detect OS version
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
  else
    msg_error "This script is designed for Debian-based systems only!"
    exit 1
  fi
  
  # Confirmation to proceed
  if ! whiptail --title "Debian Express Setup" --yesno "This script will help you set up and secure your Debian-based server.\n\nDo you want to proceed?" 10 70; then
    echo "Setup cancelled. No changes were made."
    exit 0
  fi
  
  # Create temp directory for script
  mkdir -p /tmp/debian-express-setup
  
  # Process each main section in sequence
  setup_core_configuration
  configure_network_security
  configure_additional_measures
  setup_monitoring_benchmarking
  setup_containers
  finalize_setup
}

# Run the main function
main "$@"
