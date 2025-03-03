#!/usr/bin/env bash

# Debian Express Secure
# Part 2: Security & Network Configuration Script
# Author: [Your Name]
# License: MIT
# Description: Secures and configures networking for Debian-based servers

# Define colors and formatting
RD=$(echo -e "\033[01;31m")
GN=$(echo -e "\033[1;92m")
YW=$(echo -e "\033[33m")
BL=$(echo -e "\033[1;34m")
CL=$(echo -e "\033[m")
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${YW}ℹ️${CL}"

# Create a temporary directory for storing installation states
TEMP_DIR="/tmp/debian-express"
STATE_FILE="$TEMP_DIR/installed-services.txt"
mkdir -p "$TEMP_DIR"
touch "$STATE_FILE"

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

# Function to check for root privileges
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    msg_error "This script must be run as root"
    exit 1
  fi
}

# Function to check if it's a Debian-based system
check_debian_based() {
  if [ ! -f /etc/debian_version ]; then
    msg_error "This script is designed for Debian-based systems only!"
    exit 1
  fi
}

# Detect OS version and display it
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
    return 1  # Not a Debian-based system
  fi
}

# Function to display script banner
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

  echo -e "\n${BL}Welcome to Debian Express Secure!${CL}\n"
  echo -e "Part 2: Security & Network Configuration\n"
  echo -e "This script will help you secure and configure networking on your Debian-based server."
  echo -e "This script should be run after debian-express-setup.sh.\n"
}

# Function to check if setup script was run
check_setup_script() {
  if [ ! -f "$STATE_FILE" ]; then
    whiptail --title "Warning" --yesno "It appears that debian-express-setup.sh has not been run yet or no services were installed.\n\nIt's recommended to run the setup script first. Continue anyway?" 12 70
    if [ $? -ne 0 ]; then
      echo "Please run debian-express-setup.sh first."
      exit 0
    fi
  fi
}

###################
# 1. SSH HARDENING
###################

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

#######################
# 2. FIREWALL SETUP
#######################

# Function to configure UFW with awareness of installed services
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
    
    # Auto-detect installed services and add rules
    detect_and_add_service_rules
    
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

# Function to detect installed services and add firewall rules
detect_and_add_service_rules() {
  # List of rules to add (service name, port, protocol, description)
  declare -a detected_services
  
  # Read from the state file created by the setup script
  if [ -f "$STATE_FILE" ]; then
    while IFS=: read -r service port; do
      case "$service" in
        "webmin")
          detected_services+=("Webmin" "$port" "tcp" "Webmin admin panel")
          ;;
        "easypanel")
          detected_services+=("Easy Panel" "$port" "tcp" "Easy Panel")
          ;;
        "dockge")
          detected_services+=("Dockge" "$port" "tcp" "Dockge container manager")
          ;;
        "docker")
          # Only add Docker API if explicitly configured to be exposed
          if grep -q "^tcp://" /etc/docker/daemon.json 2>/dev/null; then
            detected_services+=("Docker API" "$port" "tcp" "Docker API (caution: should be restricted)")
          fi
          ;;
      esac
    done < "$STATE_FILE"
  fi
  
  # Additional detection for services that might not be in the state file
  
  # Check for Webmin
  if systemctl is-active --quiet webmin || [ -f /etc/webmin/miniserv.conf ]; then
    webmin_port=$(grep "^port=" /etc/webmin/miniserv.conf 2>/dev/null | cut -d= -f2)
    webmin_port=${webmin_port:-10000}  # Default to 10000 if not found
    # Check if already in the array
    if ! [[ " ${detected_services[@]} " =~ " Webmin " ]]; then
      detected_services+=("Webmin" "$webmin_port" "tcp" "Webmin admin panel")
    fi
  fi
  
  # Check for Easy Panel
  if [ -d /opt/easypanel ] || docker ps 2>/dev/null | grep -q "easypanel"; then
    # Check if already in the array
    if ! [[ " ${detected_services[@]} " =~ " Easy Panel " ]]; then
      detected_services+=("Easy Panel" "3000" "tcp" "Easy Panel")
    fi
  fi
  
  # Check for Dockge
  if docker ps 2>/dev/null | grep -q "dockge"; then
    # Check if already in the array
    if ! [[ " ${detected_services[@]} " =~ " Dockge " ]]; then
      detected_services+=("Dockge" "5001" "tcp" "Dockge container manager")
    fi
  fi
  
  # If we found services, ask user to confirm adding rules
  if [ ${#detected_services[@]} -gt 0 ]; then
    # Build the message for whiptail
    services_message="Detected installed services:\n\n"
    for ((i=0; i<${#detected_services[@]}; i+=4)); do
      services_message+="• ${detected_services[i]}: Port ${detected_services[i+1]}/$(printf '%s' "${detected_services[i+2]}")\n"
    done
    services_message+="\nWould you like to add firewall rules for these services?"
    
    if whiptail --title "Detected Services" --yesno "$services_message" 15 70; then
      for ((i=0; i<${#detected_services[@]}; i+=4)); do
        service=${detected_services[i]}
        port=${detected_services[i+1]}
        protocol=${detected_services[i+2]}
        description=${detected_services[i+3]}
        
        ufw allow "$port"/"$protocol" comment "$description"
        msg_ok "Added rule for $service (Port $port/$protocol)"
      done
    else
      msg_info "Skipped adding rules for detected services"
    fi
  fi
}

#######################
# 3. FAIL2BAN SETUP
#######################

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

###################
# 4. VPN SETUP
###################

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
    
    # Create info file for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/tailscale.txt" << EOF
Tailscale VPN has been configured successfully.

Your Tailscale IP: $tailscale_ip
Tailscale subnet: $tailscale_subnet

You can now connect to this server securely via the Tailscale network.
EOF

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
      
      # Create info file for summary
      mkdir -p "$TEMP_DIR/info"
      cat > "$TEMP_DIR/info/netbird.txt" << EOF
Netbird VPN has been configured successfully.

Your Netbird IP: $netbird_ip
Netbird subnet: $netbird_subnet

You can now connect to this server securely via the Netbird network.
EOF

      whiptail --title "Netbird Configured" --msgbox "Netbird has been successfully configured.\n\nYour Netbird IP: $netbird_ip\nNetbird subnet: $netbird_subnet\n\nYou can now connect to this server securely via the Netbird network." 12 70
    else
      msg_error "Netbird setup key not provided"
    fi
  else
    msg_error "Netbird installation failed"
  fi
}

##############################
# 5. AUTOMATIC SECURITY UPDATES
##############################

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
    
    # Create info file for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/auto-updates.txt" << EOF
Automatic security updates have been configured.

Package lists update: Daily
Security updates: Enabled
Cleanup interval: Weekly
Automatic reboot: $(grep -q "Automatic-Reboot \"true\"" /etc/apt/apt.conf.d/50unattended-upgrades && echo "Enabled at $reboot_time" || echo "Disabled")
EOF

    msg_ok "Automatic security updates configured successfully"
  else
    msg_info "Automatic security updates not configured"
  fi
}

#########################
# SUMMARY AND COMPLETION
#########################

# Function to display security summary
display_security_summary() {
  # Get server IP
  server_ip=$(hostname -I | awk '{print $1}')
  
  # Build summary information
  summary="=== Debian Express Security Summary ===\n\n"
  summary+="System Information:\n"
  summary+="• Hostname: $(hostname)\n"
  summary+="• IP Address: $server_ip\n"
  summary+="• OS: $(lsb_release -ds)\n\n"
  
  # Check what was configured
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
    if grep -q "AllowUsers" /etc/ssh/sshd_config.d/50-security.conf; then
      allowed_users=$(grep "AllowUsers" /etc/ssh/sshd_config.d/50-security.conf | cut -d' ' -f2-)
      summary+="  - Allowed users: $allowed_users\n"
    fi
  else
    summary+="• SSH: Standard configuration\n"
  fi
  
  # Passwordless sudo
  if ls /etc/sudoers.d/99-*-nopasswd 2>/dev/null >/dev/null; then
    passwordless_users=$(ls /etc/sudoers.d/99-*-nopasswd | sed 's/.*99-\(.*\)-nopasswd/\1/')
    summary+="• Passwordless sudo: Enabled for users: $passwordless_users\n"
  else
    summary+="• Passwordless sudo: Not configured\n"
  fi
  
  # Firewall status
  ufw_status=$(ufw status | head -1)
  if [[ "$ufw_status" == *"active"* ]]; then
    summary+="• Firewall (UFW): Enabled\n"
    # Get firewall rules and format them
    ufw_rules=$(ufw status | grep -v "Status:" | sed 's/^/    /')
    summary+="  - Rules:\n$ufw_rules\n"
  else
    summary+="• Firewall (UFW): Disabled\n"
  fi
  
  # Fail2Ban status
  if systemctl is-active --quiet fail2ban; then
    summary+="• Fail2Ban: Active\n"
    if [ -f /etc/fail2ban/jail.local ]; then
      ban_time=$(grep "^bantime" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      find_time=$(grep "^findtime" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      max_retry=$(grep "^maxretry" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      summary+="  - Settings: Ban time = ${ban_time}s, Find time = ${find_time}s, Max retries = $max_retry\n"
    fi
  else
    summary+="• Fail2Ban: Not configured\n"
  fi
  
  # VPN status
  if systemctl is-active --quiet tailscale; then
    summary+="• VPN: Tailscale active (IP: $(tailscale ip))\n"
  elif systemctl is-active --quiet netbird; then
    summary+="• VPN: Netbird active\n"
  else
    summary+="• VPN: Not configured\n"
  fi
  
  # Automatic updates
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    summary+="• Automatic updates: Configured\n"
    if grep -q "Automatic-Reboot \"true\"" /etc/apt/apt.conf.d/50unattended-upgrades; then
      reboot_time=$(grep "Automatic-Reboot-Time" /etc/apt/apt.conf.d/50unattended-upgrades | grep -v "^//" | sed 's/.*"\(.*\)".*/\1/')
      summary+="  - Automatic reboot: Enabled ($reboot_time)\n"
    else
      summary+="  - Automatic reboot: Disabled\n"
    fi
  else
    summary+="• Automatic updates: Not configured\n"
  fi
  
  # Add detailed information if available
  if [ -d "$TEMP_DIR/info" ]; then
    summary+="\n=== Detailed Information ===\n\n"
    
    # Add VPN info
    if [ -f "$TEMP_DIR/info/tailscale.txt" ]; then
      summary+="Tailscale VPN:\n"
      summary+=$(cat "$TEMP_DIR/info/tailscale.txt")
      summary+="\n\n"
    elif [ -f "$TEMP_DIR/info/netbird.txt" ]; then
      summary+="Netbird VPN:\n"
      summary+=$(cat "$TEMP_DIR/info/netbird.txt")
      summary+="\n\n"
    fi
    
    # Add auto-updates info
    if [ -f "$TEMP_DIR/info/auto-updates.txt" ]; then
      summary+="Automatic Updates:\n"
      summary+=$(cat "$TEMP_DIR/info/auto-updates.txt")
      summary+="\n\n"
    fi
  fi
  
  # Display final summary
  whiptail --title "Security Setup Complete" --scrolltext --msgbox "$summary" 24 78
  
  # Ask if user wants to save the summary to a file
  if whiptail --title "Save Summary" --yesno "Would you like to save this summary to a file?" 8 60; then
    summary_file="/root/debian-express-security-summary.txt"
    echo -e "$summary" > "$summary_file"
    chmod 600 "$summary_file"
    msg_ok "Summary saved to $summary_file"
  fi
}

# Function to clean up and complete setup
finalize_security_setup() {
  msg_info "Finalizing security setup..."
  
  # System cleanup
  apt autoremove -y
  apt clean
  
  # Generate and display the summary
  display_security_summary
  
  msg_ok "Debian Express Security setup completed successfully!"
  echo
  echo "Your server has been secured according to your preferences."
  echo "Please review the summary information provided."
  echo
  echo "For security changes to fully apply, it's recommended to reboot your server."
  echo
  read -p "Would you like to reboot now? (y/N): " reboot_choice
  if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
    echo "Rebooting system in 5 seconds..."
    sleep 5
    reboot
  else
    echo "Please remember to reboot your system manually when convenient."
  fi
}

# Main function to orchestrate the security setup process
main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  check_setup_script
  
  # Confirmation to proceed
  if ! whiptail --title "Debian Express Security" --yesno "This script will help you secure your Debian-based server.\n\nDo you want to proceed?" 10 70; then
    echo "Setup cancelled. No changes were made."
    exit 0
  fi
  
  # SSH hardening
  configure_ssh_security
  
  # Firewall configuration
  configure_firewall
  
  # Install and configure Fail2Ban
  setup_fail2ban
  
  # VPN setup
  setup_vpn
  
  # Automatic security updates
  setup_auto_updates
  
  # Finalize setup
  finalize_security_setup
}

# Run the main function
main "$@"
