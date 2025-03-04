#!/usr/bin/env bash

# Debian Express Secure
# Security & Network Configuration Script
# Author: [Your Name]
# License: MIT
# Description: Secures and configures networking for Debian-based servers

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

# Create a temporary directory for storing installation states
TEMP_DIR="/tmp/debian-express"
STATE_FILE="$TEMP_DIR/installed-services.txt"
mkdir -p "$TEMP_DIR"
touch "$STATE_FILE"

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

# Function to get yes/no input from user
get_yes_no() {
  local prompt="$1"
  local response
  
  while true; do
    echo -e -n "${prompt} (${HIGHLIGHT}y${CL}/${HIGHLIGHT}n${CL}): "
    read -r response
    case $response in
      [Yy]* ) echo; return 0 ;;
      [Nn]* ) echo; return 1 ;;
      * ) echo "Please answer yes or no." ;;
    esac
  done
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

  echo -e "\n${BL}Security & Network Configuration${CL}\n"
}

# Function to check if setup script was run
check_setup_script() {
  if [ ! -f "$STATE_FILE" ]; then
    if get_yes_no "It appears that debian-express-setup.sh has not been run yet or no services were installed. It's recommended to run the setup script first. Continue anyway?"; then
      return 0
    else
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
  echo "Select SSH security options to configure:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Disable root SSH login (recommended)"
  echo -e "${HIGHLIGHT}2${CL}) Enable public key authentication (recommended)"
  echo -e "${HIGHLIGHT}3${CL}) Disable password authentication (requires SSH keys)"
  echo -e "${HIGHLIGHT}4${CL}) Limit SSH access to specific users"
  echo -e "${HIGHLIGHT}5${CL}) Set up SSH keys for a user"
  echo
  echo "Enter your selections (e.g., 125 for options 1, 2, and 5):"
  read -r ssh_selections
  echo
  
  # Create directory for custom SSH config
  mkdir -p /etc/ssh/sshd_config.d
  
  # Process SSH options
  if [[ $ssh_selections == *"1"* ]]; then
    echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
    msg_ok "Root SSH login disabled"
  fi
  
  if [[ $ssh_selections == *"2"* ]]; then
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
    msg_ok "Public key authentication enabled"
  fi
  
  if [[ $ssh_selections == *"3"* ]]; then
    # Check if we're setting up SSH keys to prevent lockouts
    if [[ $ssh_selections != *"5"* ]]; then
      if ! get_yes_no "You're about to disable password authentication without setting up SSH keys. This could lock you out of your server if SSH keys aren't already configured. Are you sure you want to continue?"; then
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
  
  if [[ $ssh_selections == *"4"* ]]; then
    # Get list of non-system users
    existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
    
    if [ -z "$existing_users" ]; then
      msg_error "No non-system users found"
    else
      echo "Select users allowed to access via SSH:"
      echo
      
      # Display list of users
      user_num=1
      declare -A user_map
      for user in $existing_users; do
        echo -e "${HIGHLIGHT}$user_num${CL}) $user"
        user_map[$user_num]=$user
        ((user_num++))
      done
      
      echo
      echo "Enter user numbers (e.g., 123 for users 1, 2, and 3):"
      read -r user_selections
      echo
      
      selected_users=""
      for ((i=0; i<${#user_selections}; i++)); do
        num="${user_selections:$i:1}"
        if [[ $num =~ [0-9] && -n "${user_map[$num]}" ]]; then
          selected_users+="${user_map[$num]} "
        fi
      done
      
      if [ -n "$selected_users" ]; then
        # Format the list correctly for sshd_config
        formatted_users=$(echo $selected_users | tr ' ' ',')
        echo "AllowUsers $formatted_users" >> /etc/ssh/sshd_config.d/50-security.conf
        msg_ok "SSH access limited to: $formatted_users"
      else
        msg_info "No valid users selected"
      fi
    fi
  fi
  
  # Set up SSH keys for a user if selected
  if [[ $ssh_selections == *"5"* ]]; then
    setup_ssh_keys
  fi
  
  # After configuring SSH, ask about passwordless sudo
  setup_passwordless_sudo
  
  # Restart SSH service
  systemctl restart ssh
  
  # Display current SSH configuration
  current_settings=$(sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication|port|allowusers')
  
  echo "SSH has been configured with the following settings:"
  echo
  echo "$current_settings"
  echo
  echo "Keep this terminal window open and verify you can connect with a new SSH session before closing."
  echo
  
  msg_ok "SSH configuration completed"
}

# Function to set up SSH keys for a user
setup_ssh_keys() {
  # Get list of non-system users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  
  if [ -z "$existing_users" ]; then
    msg_error "No non-system users found"
    return
  fi
  
  echo "Select a user to set up SSH keys for:"
  echo
  
  # Display list of users
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
    echo "1. ON YOUR LOCAL MACHINE, first generate an SSH key if you don't already have one:"
    echo 
    echo "   ssh-keygen -t ed25519 -C \"email@example.com\""
    echo "   or"
    echo "   ssh-keygen -t rsa -b 4096 -C \"email@example.com\""
    echo
    echo "2. Then copy your key to this server with:"
    echo
    echo "   ssh-copy-id $username@SERVER_IP"
    echo
    
    if get_yes_no "Press <y> to prepare the server for SSH key authentication or <n> to cancel"; then
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
      echo
      echo "These server-side preparations will allow you to use SSH keys for login."
      echo
    else
      msg_info "SSH key setup cancelled"
    fi
  else
    msg_info "Invalid selection. SSH key setup cancelled."
  fi
}

# Function to set up passwordless sudo for SSH users
setup_passwordless_sudo() {
  # Get list of sudo-capable users
  sudo_users=$(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' ' ')
  
  if [ -z "$sudo_users" ]; then
    msg_info "No sudo users found for passwordless configuration"
    return
  fi
  
  if get_yes_no "Would you like to configure passwordless sudo for SSH users? This allows running sudo commands without entering a password. NOTE: This is most secure when SSH key authentication is enforced and password authentication is disabled."; then
    echo "Select a user to enable passwordless sudo for:"
    echo
    
    # Display list of users
    user_num=1
    declare -A user_map
    for user in $sudo_users; do
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
      
      # Check if user has SSH keys configured
      user_home=$(eval echo ~${username})
      if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
        ssh_key_status="SSH keys are properly configured for this user."
        key_warning=""
      else
        ssh_key_status="WARNING: No SSH keys detected for this user!"
        key_warning="\nEnabling passwordless sudo WITHOUT SSH key authentication is a security risk."
      fi
      
      echo -e "$ssh_key_status$key_warning"
      echo
      
      if get_yes_no "Are you sure you want to enable passwordless sudo for ${username}?"; then
        # Configure passwordless sudo
        echo "${username} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-${username}-nopasswd
        chmod 440 /etc/sudoers.d/99-${username}-nopasswd
        msg_ok "Passwordless sudo enabled for ${username}"
      else
        msg_info "Passwordless sudo configuration cancelled"
      fi
    else
      msg_info "Invalid selection. Passwordless sudo configuration cancelled."
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
  
  if get_yes_no "Would you like to configure the firewall (UFW)? Current status: $ufw_status"; then
    # Confirm the basics
    if get_yes_no "Do you want to apply the recommended basic rules? (Allow SSH, deny incoming, allow outgoing)"; then
      # Configure basic rules
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow 22/tcp comment 'SSH'
      msg_ok "Basic firewall rules configured"
    fi
    
    # Ask about common web services
    echo "Select web services to allow:"
    echo
    echo -e "${HIGHLIGHT}1${CL}) HTTP (port 80)"
    echo -e "${HIGHLIGHT}2${CL}) HTTPS (port 443)"
    echo -e "${HIGHLIGHT}3${CL}) None"
    echo
    echo -n "Enter your selections (e.g., 12 for both): "
    read -r web_selections
    echo
    
    if [[ $web_selections == *"1"* ]]; then
      ufw allow 80/tcp comment 'HTTP'
      msg_ok "HTTP traffic allowed"
    fi
    
    if [[ $web_selections == *"2"* ]]; then
      ufw allow 443/tcp comment 'HTTPS'
      msg_ok "HTTPS traffic allowed"
    fi
    
    # Auto-detect installed services and add rules
    detect_and_add_service_rules
    
    # Ask about custom port
    if get_yes_no "Do you want to allow any custom ports?"; then
      while true; do
        echo -n "Enter port number to allow (1-65535): "
        read -r port
        echo
        
        if [[ -z "$port" ]]; then
          break
        fi
        
        if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
          echo "Select protocol:"
          echo -e "${HIGHLIGHT}1${CL}) TCP only"
          echo -e "${HIGHLIGHT}2${CL}) UDP only"
          echo -e "${HIGHLIGHT}3${CL}) Both TCP and UDP"
          echo
          echo -n "Enter your selection [1-3]: "
          read -r proto_selection
          echo
          
          case $proto_selection in
            1) protocol="tcp" ;;
            2) protocol="udp" ;;
            3) protocol="both" ;;
            *) protocol="tcp" ;;
          esac
          
          echo -n "Enter a description for this rule: "
          read -r description
          echo
          
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
        else
          echo "Please enter a valid port number between 1 and 65535."
          echo
        fi
        
        if ! get_yes_no "Do you want to allow another port?"; then
          break
        fi
      done
    fi
    
    # Enable UFW if it's not already enabled
    if [[ "$ufw_status" != *"active"* ]]; then
      if get_yes_no "Do you want to enable the firewall now with the configured rules?"; then
        echo "y" | ufw enable
        msg_ok "Firewall enabled successfully"
      else
        msg_info "Firewall configured but not enabled"
      fi
    else
      if get_yes_no "Firewall is already active. Do you want to reload the configuration?"; then
        ufw reload
        msg_ok "Firewall configuration reloaded"
      fi
    fi
    
    # Show UFW rules summary
    echo "Current firewall configuration:"
    echo
    ufw status verbose
    echo
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
    echo "Detected installed services:"
    echo
    for ((i=0; i<${#detected_services[@]}; i+=4)); do
      echo -e "• ${detected_services[i]}: Port ${HIGHLIGHT}${detected_services[i+1]}/${detected_services[i+2]}${CL}"
    done
    echo
    
    if get_yes_no "Would you like to add firewall rules for these services?"; then
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
  if get_yes_no "Would you like to install and configure Fail2Ban? It helps protect your server against brute-force attacks."; then
    msg_info "Installing Fail2Ban..."
    apt install -y fail2ban
    
    # Create a local configuration
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Configure Fail2Ban settings
    echo -n "Enter ban time in seconds (default: 600): "
    read -r ban_time
    ban_time=${ban_time:-600}
    echo
    
    echo -n "Enter find time in seconds (default: 600): "
    read -r find_time
    find_time=${find_time:-600}
    echo
    
    echo -n "Enter max retry attempts (default: 5): "
    read -r max_retry
    max_retry=${max_retry:-5}
    echo
    
    # Get additional IP whitelist
    echo -n "Enter additional IPs to whitelist (space-separated, leave empty for none): "
    read -r additional_ips
    echo
    
    # Always include localhost
    whitelist_ips="127.0.0.1 ::1"
    if [[ ! -z "$additional_ips" ]]; then
      whitelist_ips="$whitelist_ips $additional_ips"
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
    
    # Save the command for adding VPN subnet to whitelist for later
    echo "To add a VPN subnet to the Fail2Ban whitelist later, use:" > "$TEMP_DIR/fail2ban_vpn.txt"
    echo "sudo fail2ban-client set sshd addignoreip VPN_SUBNET" >> "$TEMP_DIR/fail2ban_vpn.txt"
    echo "# Example: sudo fail2ban-client set sshd addignoreip 10.8.0.0/24" >> "$TEMP_DIR/fail2ban_vpn.txt"
    
    # Show status
    echo "Fail2Ban status:"
    echo
    fail2ban-client status sshd
    echo
  else
    msg_info "Fail2Ban installation skipped"
  fi
}

###################
# 4. VPN SETUP
###################

# Setup VPN function
setup_vpn() {
  echo "VPN Setup:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Tailscale (easy to use, managed service)"
  echo -e "${HIGHLIGHT}2${CL}) Netbird (open-source, self-hostable)"
  echo -e "${HIGHLIGHT}3${CL}) Skip VPN setup"
  echo
  echo -n "Select an option [1-3]: "
  read -r vpn_choice
  echo
  
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
    if get_yes_no "Do you have a Tailscale auth key? If not, select 'n' and you'll be given a URL to authenticate manually."; then
      echo -n "Enter your Tailscale auth key: "
      read -r auth_key
      echo
    fi
    
    if [[ ! -z "$auth_key" ]]; then
      tailscale up --authkey="$auth_key"
      msg_ok "Tailscale configured with auth key"
    else
      # Start Tailscale without auth key
      tailscale up
      msg_info "Tailscale started. Please authenticate using the URL above."
      echo -n "Press Enter once you've authenticated... "
      read
      echo
    fi
    
    # Get Tailscale IP and subnet
    tailscale_ip=$(tailscale ip)
    tailscale_subnet="100.64.0.0/10"  # Default Tailscale subnet
    
    # Save command for allowing VPN subnet in firewall for later
    mkdir -p "$TEMP_DIR"
    echo "# To allow traffic from the Tailscale VPN subnet in UFW:" > "$TEMP_DIR/vpn_firewall.txt"
    echo "sudo ufw allow from $tailscale_subnet comment 'Tailscale VPN subnet'" >> "$TEMP_DIR/vpn_firewall.txt"
    
    # Create info file for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/tailscale.txt" << EOF
Tailscale VPN has been configured successfully.

Your Tailscale IP: $tailscale_ip
Tailscale subnet: $tailscale_subnet

You can now connect to this server securely via the Tailscale network.

To allow all traffic from the Tailscale subnet in your firewall:
sudo ufw allow from $tailscale_subnet comment 'Tailscale VPN subnet'

To add the Tailscale subnet to Fail2Ban whitelist:
sudo fail2ban-client set sshd addignoreip $tailscale_subnet
EOF

    echo "Tailscale has been successfully configured."
    echo
    echo -e "Your Tailscale IP: ${HIGHLIGHT}$tailscale_ip${CL}"
    echo -e "Tailscale subnet: ${HIGHLIGHT}$tailscale_subnet${CL}"
    echo
    echo "You can now connect to this server securely via the Tailscale network."
    echo
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
    
    echo -n "Enter your Netbird setup key: "
    read -r setup_key
    echo
    
    if [[ ! -z "$setup_key" ]]; then
      netbird up --setup-key "$setup_key"
      msg_ok "Netbird configured with setup key"
      
      # Get Netbird IP and subnet
      netbird_ip=$(ip addr show netbird0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "Unknown")
      
      echo -n "Enter your Netbird IP range (e.g., 100.92.0.0/16): "
      read -r netbird_subnet
      netbird_subnet=${netbird_subnet:-"100.92.0.0/16"}
      echo
      
      # Save command for allowing VPN subnet in firewall for later
      mkdir -p "$TEMP_DIR"
      echo "# To allow traffic from the Netbird VPN subnet in UFW:" > "$TEMP_DIR/vpn_firewall.txt"
      echo "sudo ufw allow from $netbird_subnet comment 'Netbird VPN subnet'" >> "$TEMP_DIR/
      ##############################
# 5. AUTOMATIC SECURITY UPDATES
##############################

# Function to set up automatic security updates
setup_auto_updates() {
  if get_yes_no "Would you like to configure automatic security updates?"; then
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
    if get_yes_no "Would you like to enable automatic reboot when necessary? This will reboot the system automatically if an update requires it."; then
      sed -i 's|//Unattended-Upgrade::Automatic-Reboot "false";|Unattended-Upgrade::Automatic-Reboot "true";|' /etc/apt/apt.conf.d/50unattended-upgrades
      
      # Ask about reboot time
      echo -n "Enter preferred reboot time (24-hour format, e.g., 02:00): "
      read -r reboot_time
      reboot_time=${reboot_time:-"02:00"}
      echo
      
      sed -i "s|//Unattended-Upgrade::Automatic-Reboot-Time \"02:00\";|Unattended-Upgrade::Automatic-Reboot-Time \"$reboot_time\";|" /etc/apt/apt.conf.d/50unattended-upgrades
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
  
  echo
  echo "=== Debian Express Security Summary ==="
  echo
  echo "System Information:"
  echo "• Hostname: $(hostname)"
  echo "• IP Address: $server_ip"
  echo "• OS: $(lsb_release -ds)"
  echo
  
  # Check what was configured
  echo "Security Configuration:"
  
  # SSH status
  if [ -f /etc/ssh/sshd_config.d/50-security.conf ]; then
    echo "• SSH: Hardened configuration applied"
    if grep -q "PasswordAuthentication no" /etc/ssh/sshd_config.d/50-security.conf; then
      echo "  - Password authentication: Disabled"
    else
      echo "  - Password authentication: Enabled"
    fi
    if grep -q "PermitRootLogin no" /etc/ssh/sshd_config.d/50-security.conf; then
      echo "  - Root login: Disabled"
    fi
    if grep -q "AllowUsers" /etc/ssh/sshd_config.d/50-security.conf; then
      allowed_users=$(grep "AllowUsers" /etc/ssh/sshd_config.d/50-security.conf | cut -d' ' -f2-)
      echo "  - Allowed users: $allowed_users"
    fi
  else
    echo "• SSH: Standard configuration"
  fi
  
  # Passwordless sudo
  if ls /etc/sudoers.d/99-*-nopasswd 2>/dev/null >/dev/null; then
    passwordless_users=$(ls /etc/sudoers.d/99-*-nopasswd | sed 's/.*99-\(.*\)-nopasswd/\1/')
    echo "• Passwordless sudo: Enabled for users: $passwordless_users"
  else
    echo "• Passwordless sudo: Not configured"
  fi
  
  # Firewall status
  ufw_status=$(ufw status | head -1)
  if [[ "$ufw_status" == *"active"* ]]; then
    echo "• Firewall (UFW): Enabled"
    echo "  - Rules:"
    ufw status | grep -v "Status:" | sed 's/^/    /'
    echo
  else
    echo "• Firewall (UFW): Disabled"
  fi
  
  # Fail2Ban status
  if systemctl is-active --quiet fail2ban; then
    echo "• Fail2Ban: Active"
    if [ -f /etc/fail2ban/jail.local ]; then
      ban_time=$(grep "^bantime" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      find_time=$(grep "^findtime" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      max_retry=$(grep "^maxretry" /etc/fail2ban/jail.local | head -1 | awk '{print $3}')
      echo "  - Settings: Ban time = ${ban_time}s, Find time = ${find_time}s, Max retries = $max_retry"
    fi
  else
    echo "• Fail2Ban: Not configured"
  fi
  
  # VPN status
  if systemctl is-active --quiet tailscale; then
    echo "• VPN: Tailscale active (IP: $(tailscale ip))"
  elif systemctl is-active --quiet netbird; then
    echo "• VPN: Netbird active"
  else
    echo "• VPN: Not configured"
  fi
  
  # Automatic updates
  if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
    echo "• Automatic updates: Configured"
    if grep -q "Automatic-Reboot \"true\"" /etc/apt/apt.conf.d/50unattended-upgrades; then
      reboot_time=$(grep "Automatic-Reboot-Time" /etc/apt/apt.conf.d/50unattended-upgrades | grep -v "^//" | sed 's/.*"\(.*\)".*/\1/')
      echo "  - Automatic reboot: Enabled ($reboot_time)"
    else
      echo "  - Automatic reboot: Disabled"
    fi
  else
    echo "• Automatic updates: Not configured"
  fi
  
  echo
  
  # Add detailed information if available
  if [ -d "$TEMP_DIR/info" ]; then
    echo "=== Additional Configuration Commands ==="
    echo
    
    # Add VPN firewall commands
    if [ -f "$TEMP_DIR/vpn_firewall.txt" ]; then
      echo "VPN Firewall Rules:"
      cat "$TEMP_DIR/vpn_firewall.txt"
      echo
    fi
    
    # Add Fail2Ban VPN whitelist commands
    if [ -f "$TEMP_DIR/fail2ban_vpn.txt" ]; then
      echo "Fail2Ban VPN Whitelist:"
      cat "$TEMP_DIR/fail2ban_vpn.txt"
      echo
    fi
    
    # Add VPN info
    if [ -f "$TEMP_DIR/info/tailscale.txt" ]; then
      echo "Tailscale VPN Configuration:"
      grep "To allow all\|To add the" "$TEMP_DIR/info/tailscale.txt"
      echo
    elif [ -f "$TEMP_DIR/info/netbird.txt" ]; then
      echo "Netbird VPN Configuration:"
      grep "To allow all\|To add the" "$TEMP_DIR/info/netbird.txt"
      echo
    fi
  fi
  
  # Save summary to file
  echo "=== Debian Express Security Summary ===" > "$TEMP_DIR/security_summary.txt"
  echo >> "$TEMP_DIR/security_summary.txt"
  echo "Full security summary available at: /root/debian-express-security-summary.txt" >> "$TEMP_DIR/security_summary.txt"
}

# Function to clean up and complete setup
finalize_security_setup() {
  msg_info "Finalizing security setup..."
  
  # System cleanup
  apt autoremove -y
  apt clean
  
  # Generate and display the summary
  display_security_summary
  
  # Save complete summary to file
  summary_file="/root/debian-express-security-summary.txt"
  cp "$TEMP_DIR/security_summary.txt" "$summary_file"
  chmod 600 "$summary_file"
  
  msg_ok "Debian Express Security setup completed successfully!"
  echo
  echo "Your server has been secured according to your preferences."
  echo "Please review the summary information provided."
  echo
  echo "For security changes to fully apply, it's recommended to reboot your server."
  echo
  echo -n "Would you like to reboot now? (y/N): "
  read -r reboot_choice
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
  if ! get_yes_no "This script will help you secure your Debian-based server. Do you want to proceed?"; then
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
main "$@"#!/usr/bin/env bash

# Debian Express Secure
# Security & Network Configuration Script
# Author: [Your Name]
# License: MIT
# Description: Secures and configures networking for Debian-based servers

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

# Create a temporary directory for storing installation states
TEMP_DIR="/tmp/debian-express"
STATE_FILE="$TEMP_DIR/installed-services.txt"
mkdir -p "$TEMP_DIR"
touch "$STATE_FILE"

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

# Function to get yes/no input from user
get_yes_no() {
  local prompt="$1"
  local response
  
  while true; do
    echo -e -n "${prompt} (${HIGHLIGHT}y${CL}/${HIGHLIGHT}n${CL}): "
    read -r response
    case $response in
      [Yy]* ) echo; return 0 ;;
      [Nn]* ) echo; return 1 ;;
      * ) echo "Please answer yes or no." ;;
    esac
  done
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

  echo -e "\n${BL}Security & Network Configuration${CL}\n"
}

# Function to check if setup script was run
check_setup_script() {
  if [ ! -f "$STATE_FILE" ]; then
    if get_yes_no "It appears that debian-express-setup.sh has not been run yet or no services were installed. It's recommended to run the setup script first. Continue anyway?"; then
      return 0
    else
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
  echo "Select SSH security options to configure:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Disable root SSH login (recommended)"
  echo -e "${HIGHLIGHT}2${CL}) Enable public key authentication (recommended)"
  echo -e "${HIGHLIGHT}3${CL}) Disable password authentication (requires SSH keys)"
  echo -e "${HIGHLIGHT}4${CL}) Limit SSH access to specific users"
  echo -e "${HIGHLIGHT}5${CL}) Set up SSH keys for a user"
  echo
  echo "Enter your selections (e.g., 125 for options 1, 2, and 5):"
  read -r ssh_selections
  echo
  
  # Create directory for custom SSH config
  mkdir -p /etc/ssh/sshd_config.d
  
  # Process SSH options
  if [[ $ssh_selections == *"1"* ]]; then
    echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
    msg_ok "Root SSH login disabled"
  fi
  
  if [[ $ssh_selections == *"2"* ]]; then
    echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
    msg_ok "Public key authentication enabled"
  fi
  
  if [[ $ssh_selections == *"3"* ]]; then
    # Check if we're setting up SSH keys to prevent lockouts
    if [[ $ssh_selections != *"5"* ]]; then
      if ! get_yes_no "You're about to disable password authentication without setting up SSH keys. This could lock you out of your server if SSH keys aren't already configured. Are you sure you want to continue?"; then
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
  
  if [[ $ssh_selections == *"4"* ]]; then
    # Get list of non-system users
    existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
    
    if [ -z "$existing_users" ]; then
      msg_error "No non-system users found"
    else
      echo "Select users allowed to access via SSH:"
      echo
      
      # Display list of users
      user_num=1
      declare -A user_map
      for user in $existing_users; do
        echo -e "${HIGHLIGHT}$user_num${CL}) $user"
        user_map[$user_num]=$user
        ((user_num++))
      done
      
      echo
      echo "Enter user numbers (e.g., 123 for users 1, 2, and 3):"
      read -r user_selections
      echo
      
      selected_users=""
      for ((i=0; i<${#user_selections}; i++)); do
        num="${user_selections:$i:1}"
        if [[ $num =~ [0-9] && -n "${user_map[$num]}" ]]; then
          selected_users+="${user_map[$num]} "
        fi
      done
      
      if [ -n "$selected_users" ]; then
        # Format the list correctly for sshd_config
        formatted_users=$(echo $selected_users | tr ' ' ',')
        echo "AllowUsers $formatted_users" >> /etc/ssh/sshd_config.d/50-security.conf
        msg_ok "SSH access limited to: $formatted_users"
      else
        msg_info "No valid users selected"
      fi
    fi
  fi
  
  # Set up SSH keys for a user if selected
  if [[ $ssh_selections == *"5"* ]]; then
    setup_ssh_keys
  fi
  
  # After configuring SSH, ask about passwordless sudo
  setup_passwordless_sudo
  
  # Restart SSH service
  systemctl restart ssh
  
  # Display current SSH configuration
  current_settings=$(sshd -T | grep -E 'permitrootlogin|pubkeyauthentication|passwordauthentication|port|allowusers')
  
  echo "SSH has been configured with the following settings:"
  echo
  echo "$current_settings"
  echo
  echo "Keep this terminal window open and verify you can connect with a new SSH session before closing."
  echo
  
  msg_ok "SSH configuration completed"
}

# Function to set up SSH keys for a user
setup_ssh_keys() {
  # Get list of non-system users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  
  if [ -z "$existing_users" ]; then
    msg_error "No non-system users found"
    return
  fi
  
  echo "Select a user to set up SSH keys for:"
  echo
  
  # Display list of users
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
    echo "1. ON YOUR LOCAL MACHINE, first generate an SSH key if you don't already have one:"
    echo 
    echo "   ssh-keygen -t ed25519 -C \"email@example.com\""
    echo "   or"
    echo "   ssh-keygen -t rsa -b 4096 -C \"email@example.com\""
    echo
    echo "2. Then copy your key to this server with:"
    echo
    echo "   ssh-copy-id $username@SERVER_IP"
    echo
    
    if get_yes_no "Press <y> to prepare the server for SSH key authentication or <n> to cancel"; then
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
      echo
      echo "These server-side preparations will allow you to use SSH keys for login."
      echo
    else
      msg_info "SSH key setup cancelled"
    fi
  else
    msg_info "Invalid selection. SSH key setup cancelled."
  fi
}

# Function to set up passwordless sudo for SSH users
setup_passwordless_sudo() {
  # Get list of sudo-capable users
  sudo_users=$(grep -Po '^sudo.+:\K.*$' /etc/group | tr ',' ' ')
  
  if [ -z "$sudo_users" ]; then
    msg_info "No sudo users found for passwordless configuration"
    return
  fi
  
  if get_yes_no "Would you like to configure passwordless sudo for SSH users? This allows running sudo commands without entering a password. NOTE: This is most secure when SSH key authentication is enforced and password authentication is disabled."; then
    echo "Select a user to enable passwordless sudo for:"
    echo
    
    # Display list of users
    user_num=1
    declare -A user_map
    for user in $sudo_users; do
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
      
      # Check if user has SSH keys configured
      user_home=$(eval echo ~${username})
      if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
        ssh_key_status="SSH keys are properly configured for this user."
        key_warning=""
      else
        ssh_key_status="WARNING: No SSH keys detected for this user!"
        key_warning="\nEnabling passwordless sudo WITHOUT SSH key authentication is a security risk."
      fi
      
      echo -e "$ssh_key_status$key_warning"
      echo
      
      if get_yes_no "Are you sure you want to enable passwordless sudo for ${username}?"; then
        # Configure passwordless sudo
        echo "${username} ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/99-${username}-nopasswd
        chmod 440 /etc/sudoers.d/99-${username}-nopasswd
        msg_ok "Passwordless sudo enabled for ${username}"
      else
        msg_info "Passwordless sudo configuration cancelled"
      fi
    else
      msg_info "Invalid selection. Passwordless sudo configuration cancelled."
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
  
  if get_yes_no "Would you like to configure the firewall (UFW)? Current status: $ufw_status"; then
    # Confirm the basics
    if get_yes_no "Do you want to apply the recommended basic rules? (Allow SSH, deny incoming, allow outgoing)"; then
      # Configure basic rules
      ufw default deny incoming
      ufw default allow outgoing
      ufw allow 22/tcp comment 'SSH'
      msg_ok "Basic firewall rules configured"
    fi
    
    # Ask about common web services
    echo "Select web services to allow:"
    echo
    echo -e "${HIGHLIGHT}1${CL}) HTTP (port 80)"
    echo -e "${HIGHLIGHT}2${CL}) HTTPS (port 443)"
    echo -e "${HIGHLIGHT}3${CL}) None"
    echo
    echo -n "Enter your selections (e.g., 12 for both): "
    read -r web_selections
    echo
    
    if [[ $web_selections == *"1"* ]]; then
      ufw allow 80/tcp comment 'HTTP'
      msg_ok "HTTP traffic allowed"
    fi
    
    if [[ $web_selections == *"2"* ]]; then
      ufw allow 443/tcp comment 'HTTPS'
      msg_ok "HTTPS traffic allowed"
    fi
    
    # Auto-detect installed services and add rules
    detect_and_add_service_rules
    
    # Ask about custom port
    if get_yes_no "Do you want to allow any custom ports?"; then
      while true; do
        echo -n "Enter port number to allow (1-65535): "
        read -r port
        echo
        
        if [[ -z "$port" ]]; then
          break
        fi
        
        if [[ $port =~ ^[0-9]+$ && $port -ge 1 && $port -le 65535 ]]; then
          echo "Select protocol:"
          echo -e "${HIGHLIGHT}1${CL}) TCP only"
          echo -e "${HIGHLIGHT}2${CL}) UDP only"
          echo -e "${HIGHLIGHT}3${CL}) Both TCP and UDP"
          echo
          echo -n "Enter your selection [1-3]: "
          read -r proto_selection
          echo
          
          case $proto_selection in
            1) protocol="tcp" ;;
            2) protocol="udp" ;;
            3) protocol="both" ;;
            *) protocol="tcp" ;;
          esac
          
          echo -n "Enter a description for this rule: "
          read -r description
          echo
          
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
        else
          echo "Please enter a valid port number between 1 and 65535."
          echo
        fi
        
        if ! get_yes_no "Do you want to allow another port?"; then
          break
        fi
      done
    fi
    
    # Enable UFW if it's not already enabled
    if [[ "$ufw_status" != *"active"* ]]; then
      if get_yes_no "Do you want to enable the firewall now with the configured rules?"; then
        echo "y" | ufw enable
        msg_ok "Firewall enabled successfully"
      else
        msg_info "Firewall configured but not enabled"
      fi
    else
      if get_yes_no "Firewall is already active. Do you want to reload the configuration?"; then
        ufw reload
        msg_ok "Firewall configuration reloaded"
      fi
    fi
    
    # Show UFW rules summary
    echo "Current firewall configuration:"
    echo
    ufw status verbose
    echo
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
    echo "Detected installed services:"
    echo
    for ((i=0; i<${#detected_services[@]}; i+=4)); do
      echo -e "• ${detected_services[i]}: Port ${HIGHLIGHT}${detected_services[i+1]}/${detected_services[i+2]}${CL}"
    done
    echo
    
    if get_yes_no "Would you like to add firewall rules for these services?"; then
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
  if get_yes_no "Would you like to install and configure Fail2Ban? It helps protect your server against brute-force attacks."; then
    msg_info "Installing Fail2Ban..."
    apt install -y fail2ban
    
    # Create a local configuration
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    
    # Configure Fail2Ban settings
    echo -n "Enter ban time in seconds (default: 600): "
    read -r ban_time
    ban_time=${ban_time:-600}
    echo
    
    echo -n "Enter find time in seconds (default: 600): "
    read -r find_time
    find_time=${find_time:-600}
    echo
    
    echo -n "Enter max retry attempts (default: 5): "
    read -r max_retry
    max_retry=${max_retry:-5}
    echo
    
    # Get additional IP whitelist
    echo -n "Enter additional IPs to whitelist (space-separated, leave empty for none): "
    read -r additional_ips
    echo
    
    # Always include localhost
    whitelist_ips="127.0.0.1 ::1"
    if [[ ! -z "$additional_ips" ]]; then
      whitelist_ips="$whitelist_ips $additional_ips"
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
    
    # Save the command for adding VPN subnet to whitelist for later
    echo "To add a VPN subnet to the Fail2Ban whitelist later, use:" > "$TEMP_DIR/fail2ban_vpn.txt"
    echo "sudo fail2ban-client set sshd addignoreip VPN_SUBNET" >> "$TEMP_DIR/fail2ban_vpn.txt"
    echo "# Example: sudo fail2ban-client set sshd addignoreip 10.8.0.0/24" >> "$TEMP_DIR/fail2ban_vpn.txt"
    
    # Show status
    echo "Fail2Ban status:"
    echo
    fail2ban-client status sshd
    echo
  else
    msg_info "Fail2Ban installation skipped"
  fi
}

###################
# 4. VPN SETUP
###################

# Setup VPN function
setup_vpn() {
  echo "VPN Setup:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Tailscale (easy to use, managed service)"
  echo -e "${HIGHLIGHT}2${CL}) Netbird (open-source, self-hostable)"
  echo -e "${HIGHLIGHT}3${CL}) Skip VPN setup"
  echo
  echo -n "Select an option [1-3]: "
  read -r vpn_choice
  echo
  
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
    if get_yes_no "Do you have a Tailscale auth key? If not, select 'n' and you'll be given a URL to authenticate manually."; then
      echo -n "Enter your Tailscale auth key: "
      read -r auth_key
      echo
    fi
    
    if [[ ! -z "$auth_key" ]]; then
      tailscale up --authkey="$auth_key"
      msg_ok "Tailscale configured with auth key"
    else
      # Start Tailscale without auth key
      tailscale up
      msg_info "Tailscale started. Please authenticate using the URL above."
      echo -n "Press Enter once you've authenticated... "
      read
      echo
    fi
    
    # Get Tailscale IP and subnet
    tailscale_ip=$(tailscale ip)
    tailscale_subnet="100.64.0.0/10"  # Default Tailscale subnet
    
    # Save command for allowing VPN subnet in firewall for later
    mkdir -p "$TEMP_DIR"
    echo "# To allow traffic from the Tailscale VPN subnet in UFW:" > "$TEMP_DIR/vpn_firewall.txt"
    echo "sudo ufw allow from $tailscale_subnet comment 'Tailscale VPN subnet'" >> "$TEMP_DIR/vpn_firewall.txt"
    
    # Create info file for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/tailscale.txt" << EOF
Tailscale VPN has been configured successfully.

Your Tailscale IP: $tailscale_ip
Tailscale subnet: $tailscale_subnet

You can now connect to this server securely via the Tailscale network.

To allow all traffic from the Tailscale subnet in your firewall:
sudo ufw allow from $tailscale_subnet comment 'Tailscale VPN subnet'

To add the Tailscale subnet to Fail2Ban whitelist:
sudo fail2ban-client set sshd addignoreip $tailscale_subnet
EOF

    echo "Tailscale has been successfully configured."
    echo
    echo -e "Your Tailscale IP: ${HIGHLIGHT}$tailscale_ip${CL}"
    echo -e "Tailscale subnet: ${HIGHLIGHT}$tailscale_subnet${CL}"
    echo
    echo "You can now connect to this server securely via the Tailscale network."
    echo
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
    
    echo -n "Enter your Netbird setup key: "
    read -r setup_key
    echo
    
    if [[ ! -z "$setup_key" ]]; then
      netbird up --setup-key "$setup_key"
      msg_ok "Netbird configured with setup key"
      
      # Get Netbird IP and subnet
      netbird_ip=$(ip addr show netbird0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "Unknown")
      
      echo -n "Enter your Netbird IP range (e.g., 100.92.0.0/16): "
      read -r netbird_subnet
      netbird_subnet=${netbird_subnet:-"100.92.0.0/16"}
      echo
      
      # Save command for allowing VPN subnet in firewall for later
      mkdir -p "$TEMP_DIR"
      echo "# To allow traffic from the Netbird VPN subnet in UFW:" > "$TEMP_DIR/vpn_firewall.txt"
      echo "sudo ufw allow from $netbird_subnet comment 'Netbird VPN subnet'" >> "$TEMP_DIR/
