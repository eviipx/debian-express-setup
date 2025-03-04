#!/usr/bin/env bash

# Debian Express Secure
# Security & Network Configuration Script
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
SUMMARY_FILE="$TEMP_DIR/security-summary.txt"
mkdir -p "$TEMP_DIR"
touch "$STATE_FILE"
touch "$SUMMARY_FILE"

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

# Function to detect services from state file and running processes
detect_services() {
  msg_info "Detecting installed services..."
  
  # Create a clean temporary file for processed services
  TMP_SERVICES_FILE=$(mktemp)
  DETECTED_SERVICES_LIST=""
  
  # Track services we've already seen to prevent duplicates
  declare -A seen_services
  
  # Read from the state file created by the setup script
  if [ -f "$STATE_FILE" ]; then
    while IFS=: read -r service port; do
      if [ -n "$service" ] && [ -n "$port" ]; then
        # Skip if we've seen this service:port combination already
        service_key="${service}:${port}"
        if [ -n "${seen_services[$service_key]}" ]; then
          continue
        fi
        
        seen_services["$service_key"]=1
        echo "$service:$port" >> "$TMP_SERVICES_FILE"
        DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• ${service^}: Port ${HIGHLIGHT}${port}${CL}\n"
      fi
    done < "$STATE_FILE"
  fi
  
  # Add system-detected services only if not already in our list
  
  # Webmin
  if (systemctl is-active --quiet webmin || [ -f /etc/webmin/miniserv.conf ]); then
    webmin_port=$(grep "^port=" /etc/webmin/miniserv.conf 2>/dev/null | cut -d= -f2)
    webmin_port=${webmin_port:-10000}  # Default to 10000 if not found
    service_key="webmin:$webmin_port"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "webmin:$webmin_port" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Webmin: Port ${HIGHLIGHT}${webmin_port}${CL}\n"
    fi
  fi
  
  # Nginx
  if systemctl is-active --quiet nginx; then
    service_key="nginx:80,443"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "nginx:80,443" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Nginx: Ports ${HIGHLIGHT}80,443${CL}\n"
    fi
  fi
  
  # Apache
  if systemctl is-active --quiet apache2; then
    service_key="apache2:80,443"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "apache2:80,443" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Apache: Ports ${HIGHLIGHT}80,443${CL}\n"
    fi
  fi
  
  # Docker
  if systemctl is-active --quiet docker; then
    service_key="docker:N/A"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "docker:N/A" >> "$TMP_SERVICES_FILE" 
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker: Running${CL}\n"
      
      # Check for docker containers with exposed ports
      if command -v docker >/dev/null; then
        container_info=$(docker ps --format "{{.Names}}: {{.Ports}}" 2>/dev/null | grep -v "^$" | sort | uniq)
        if [ -n "$container_info" ]; then
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker containers with exposed ports:\n"
          while IFS= read -r line; do
            if [ -n "$line" ]; then
              DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}  - $line\n"
            fi
          done <<< "$container_info"
        fi
      fi
    fi
  fi
  
  # Load detected services into global associative array for firewall rules
  unset DETECTED_SERVICES
  declare -g -A DETECTED_SERVICES
  
  if [ -f "$TMP_SERVICES_FILE" ]; then
    while IFS=: read -r service port; do
      if [ -n "$service" ] && [ -n "$port" ]; then
        DETECTED_SERVICES["$service"]="$port"
      fi
    done < "$TMP_SERVICES_FILE"
    
    # Clean up temp file
    rm -f "$TMP_SERVICES_FILE"
  fi
  
  # If we found services, show them
  if [ -n "$DETECTED_SERVICES_LIST" ]; then
    echo "Detected installed services:"
    echo -e "$DETECTED_SERVICES_LIST"
  else
    echo "No services detected."
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
  
  # Create directory for custom SSH config
  mkdir -p /etc/ssh/sshd_config.d
  
  # Step 1: Check for non-root users before disabling root login
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  current_user=$(whoami)
  
  if [ "$current_user" = "root" ] && [ -z "$existing_users" ]; then
    msg_error "No non-root users detected. Creating a non-root user is required before disabling root login."
    echo "Would you like to create a non-root user with sudo privileges now?"
    if get_yes_no "Create a non-root sudo user?"; then
      echo -n "Enter username for new sudo user: "
      read -r new_username
      echo
      
      if [ -z "$new_username" ]; then
        msg_error "No username provided. Keeping root login enabled."
      else
        adduser "$new_username"
        usermod -aG sudo "$new_username"
        apt install -y sudo  # Ensure sudo is installed
        msg_ok "User $new_username created with sudo privileges"
        existing_users="$new_username"
      fi
    else
      msg_info "Keeping root login enabled. It's recommended to create a non-root user before disabling root login."
    fi
  fi
  
  # Now check if we can safely disable root login
  if [ "$current_user" != "root" ] || [ -n "$existing_users" ]; then
    if get_yes_no "Disable root SSH login? (Recommended for security)"; then
      echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Root SSH login disabled"
      echo "Root SSH login: Disabled" >> "$SUMMARY_FILE"
    else
      msg_info "Root SSH login remains enabled"
      echo "Root SSH login: Enabled" >> "$SUMMARY_FILE"
    fi
  fi
  
  # Step 2: SSH key setup
  echo "Checking for existing SSH keys..."
  
  has_ssh_keys=false
  for user in $existing_users; do
    user_home=$(eval echo ~${user})
    if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
      has_ssh_keys=true
      msg_ok "SSH keys found for user: $user"
    fi
  done
  
  if [ "$has_ssh_keys" = false ]; then
    msg_info "No SSH keys detected for any users"
    
    if get_yes_no "Would you like to set up SSH key authentication? (Recommended)"; then
      while true; do
        setup_ssh_keys
        
        # Check if keys were setup successfully
        for user in $existing_users; do
          user_home=$(eval echo ~${user})
          if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
            has_ssh_keys=true
            msg_ok "SSH keys verified for user: $user"
            echo "SSH keys: Configured for user $user" >> "$SUMMARY_FILE"
            break
          fi
        done
        
        if [ "$has_ssh_keys" = true ]; then
          break
        else
          if get_yes_no "SSH keys not detected. Would you like to try again?"; then
            continue
          else
            msg_info "Skipping SSH key setup"
            echo "SSH keys: Not configured" >> "$SUMMARY_FILE"
            break
          fi
        fi
      done
    else
      echo "SSH keys: Not configured" >> "$SUMMARY_FILE"
    fi
  else
    echo "SSH keys: Already configured" >> "$SUMMARY_FILE"
  fi
  
  # Step 3: Enable public key authentication
  echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
  msg_ok "Public key authentication enabled"
  echo "Public key authentication: Enabled" >> "$SUMMARY_FILE"
  
  # Step 4: Disable password authentication (only if SSH keys are set up)
  if [ "$has_ssh_keys" = true ]; then
    if get_yes_no "SSH keys detected. Would you like to disable password authentication? (Recommended when using SSH keys)"; then
      echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Password authentication disabled"
      echo "Password authentication: Disabled" >> "$SUMMARY_FILE"
    else
      msg_info "Password authentication remains enabled"
      echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
    fi
  else
    msg_info "Password authentication remains enabled (SSH keys not detected)"
    echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
  fi
  
  # Step 5: Limit SSH access to specific users
  if get_yes_no "Would you like to limit SSH access to specific users?"; then
    # Get list of non-system users
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
        echo "SSH access limited to: $formatted_users" >> "$SUMMARY_FILE"
      else
        msg_info "No valid users selected"
      fi
    fi
  else
    echo "SSH access: Not limited to specific users" >> "$SUMMARY_FILE"
  fi
  
  # Step 6: Setup passwordless sudo if using SSH keys
  if [ "$has_ssh_keys" = true ]; then
    setup_passwordless_sudo
  fi
  
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
    echo "1. ON YOUR LOCAL MACHINE, first generate an SSH key if you don't already have one: ssh-keygen -t ed25519 -C \"email@example.com\""
    echo
    echo "2. Then copy your key to this server with: ssh-copy-id $username@$(hostname -I | awk '{print $1}')"
    echo
    
    # Set up .ssh directory with correct permissions
    user_home=$(eval echo ~${username})
    mkdir -p ${user_home}/.ssh
    touch ${user_home}/.ssh/authorized_keys
    
    # Fix permissions
    chmod 700 ${user_home}/.ssh
    chmod 600 ${user_home}/.ssh/authorized_keys
    chown -R ${username}:${username} ${user_home}/.ssh
    
    msg_ok "SSH directory created with correct permissions for $username"
    
    echo "Please complete the following steps:"
    echo "1. Keep this terminal window open"
    echo "2. Open a new terminal window on your local machine"
    echo "3. Generate and copy your SSH key as shown above"
    echo "4. Return to this window when complete"
    echo
    
    if get_yes_no "Have you copied your SSH key to the server?"; then
      # Check if key was actually copied
      if [ -s "${user_home}/.ssh/authorized_keys" ]; then
        msg_ok "SSH key detected for $username"
        return 0
      else
        msg_error "No SSH key detected for $username"
        return 1
      fi
    else
      msg_info "You can complete this step later, but some security features will be unavailable until then"
      return 1
    fi
  else
    msg_info "Invalid selection. SSH key setup cancelled."
    return 1
  fi
}

# Function to set up passwordless sudo for SSH users
setup_passwordless_sudo() {
  # Get list of sudo-capable users
  sudo_users=$(grep -Po '^sudo.+:\K.*$' /etc/group 2>/dev/null | tr ',' ' ')
  
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
        echo "Passwordless sudo: Enabled for $username" >> "$SUMMARY_FILE"
      else
        msg_info "Passwordless sudo configuration cancelled"
      fi
    else
      msg_info "Invalid selection. Passwordless sudo configuration cancelled."
    fi
  else
    msg_info "Passwordless sudo configuration skipped"
    echo "Passwordless sudo: Not configured" >> "$SUMMARY_FILE"
  fi
}

#######################
# 2. FIREWALL SETUP
#######################

# Function to optionally configure UFW
configure_firewall() {
  if get_yes_no "Would you like to install and configure UFW (Uncomplicated Firewall)? Note: If you're using a cloud VPS, it might already have a firewall configured at the provider level."; then
    if ! command -v ufw >/dev/null; then
      msg_info "Installing UFW (Uncomplicated Firewall)..."
      apt install -y ufw
    fi
    
    # Check if UFW is already enabled
    ufw_status=$(ufw status | head -1)
    
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
    if [ ${#DETECTED_SERVICES[@]} -gt 0 ]; then
      echo "Detected services with following ports:"
      echo -e "$DETECTED_SERVICES_LIST"
      
      if get_yes_no "Would you like to add firewall rules for these detected services?"; then
        for service in "${!DETECTED_SERVICES[@]}"; do
          ports="${DETECTED_SERVICES[$service]}"
          
          # Skip services with N/A as port or already processed HTTP/HTTPS
          if [ "$ports" = "N/A" ] || [ "$service" = "nginx" ] || [ "$service" = "apache2" ]; then
            continue
          fi
          
          # Add multiple port entries if comma-separated
          IFS=',' read -ra PORT_ARRAY <<< "$ports"
          for port in "${PORT_ARRAY[@]}"; do
            ufw allow "$port"/tcp comment "$service"
            msg_ok "Added rule for $service (Port $port)"
          done
        done
      fi
    fi
    
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
        echo "Firewall (UFW): Enabled" >> "$SUMMARY_FILE"
      else
        msg_info "Firewall configured but not enabled"
        echo "Firewall (UFW): Configured but not enabled" >> "$SUMMARY_FILE"
      fi
    else
      if get_yes_no "Firewall is already active. Do you want to reload the configuration?"; then
        ufw reload
        msg_ok "Firewall configuration reloaded"
        echo "Firewall (UFW): Active and reloaded" >> "$SUMMARY_FILE"
      else
        echo "Firewall (UFW): Active but not reloaded" >> "$SUMMARY_FILE"
      fi
    fi
    
    # Show UFW rules summary
    echo "Current firewall configuration:"
    echo
    ufw status verbose
    echo
  else
    msg_info "UFW configuration skipped"
    echo "Firewall (UFW): Not configured" >> "$SUMMARY_FILE"
    
    # Add detected services to summary for cloud firewall reference
    if [ -n "$DETECTED_SERVICES_LIST" ]; then
      echo "Note: The following services were detected. Please ensure your cloud firewall allows these ports:" >> "$SUMMARY_FILE"
      echo -e "$DETECTED_SERVICES_LIST" >> "$SUMMARY_FILE"
    fi
  fi
}

#######################
# 3. FAIL2BAN SETUP
#######################

# Setup Fail2Ban function with simplified configuration
setup_fail2ban() {
  if get_yes_no "Would you like to install and configure Fail2Ban? It helps protect your server against brute-force attacks."; then
    msg_info "Installing Fail2Ban..."
    apt install -y fail2ban
    
    # Create a local configuration with default settings
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 10 minutes (600 seconds)
bantime = 600
# Find time window of 10 minutes
findtime = 600
# Allow 5 retries
maxretry = 5
# Ignore localhost
ignoreip = 127.0.0.1 ::1
EOF
    
    # Ask for IP whitelist
    echo -n "Enter IPs or ranges to whitelist (space-separated, leave empty for none): "
    read -r whitelist_ips
    echo
    
    if [[ -n "$whitelist_ips" ]]; then
      # Append to ignoreip
      sed -i "s/ignoreip = 127.0.0.1 ::1/ignoreip = 127.0.0.1 ::1 $whitelist_ips/" /etc/fail2ban/jail.local
      msg_ok "Added whitelisted IPs: $whitelist_ips"
      echo "Fail2Ban whitelist: $whitelist_ips" >> "$SUMMARY_FILE"
    fi
    
    # Add SSH jail
    cat >> /etc/fail2ban/jail.local << EOF

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF
    
    # Enable and start Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    msg_ok "Fail2Ban installed and configured with default settings"
    echo "Fail2Ban: Installed and active" >> "$SUMMARY_FILE"
    echo "Fail2Ban settings:
    #!/usr/bin/env bash

# Debian Express Secure
# Security & Network Configuration Script
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
SUMMARY_FILE="$TEMP_DIR/security-summary.txt"
mkdir -p "$TEMP_DIR"
touch "$STATE_FILE"
touch "$SUMMARY_FILE"

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

# Function to detect services from state file and running processes
detect_services() {
  msg_info "Detecting installed services..."
  
  # Create a clean temporary file for processed services
  TMP_SERVICES_FILE=$(mktemp)
  DETECTED_SERVICES_LIST=""
  
  # Track services we've already seen to prevent duplicates
  declare -A seen_services
  
  # Read from the state file created by the setup script
  if [ -f "$STATE_FILE" ]; then
    while IFS=: read -r service port; do
      if [ -n "$service" ] && [ -n "$port" ]; then
        # Skip if we've seen this service:port combination already
        service_key="${service}:${port}"
        if [ -n "${seen_services[$service_key]}" ]; then
          continue
        fi
        
        seen_services["$service_key"]=1
        echo "$service:$port" >> "$TMP_SERVICES_FILE"
        DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• ${service^}: Port ${HIGHLIGHT}${port}${CL}\n"
      fi
    done < "$STATE_FILE"
  fi
  
  # Add system-detected services only if not already in our list
  
  # Webmin
  if (systemctl is-active --quiet webmin || [ -f /etc/webmin/miniserv.conf ]); then
    webmin_port=$(grep "^port=" /etc/webmin/miniserv.conf 2>/dev/null | cut -d= -f2)
    webmin_port=${webmin_port:-10000}  # Default to 10000 if not found
    service_key="webmin:$webmin_port"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "webmin:$webmin_port" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Webmin: Port ${HIGHLIGHT}${webmin_port}${CL}\n"
    fi
  fi
  
  # Nginx
  if systemctl is-active --quiet nginx; then
    service_key="nginx:80,443"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "nginx:80,443" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Nginx: Ports ${HIGHLIGHT}80,443${CL}\n"
    fi
  fi
  
  # Apache
  if systemctl is-active --quiet apache2; then
    service_key="apache2:80,443"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "apache2:80,443" >> "$TMP_SERVICES_FILE"
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Apache: Ports ${HIGHLIGHT}80,443${CL}\n"
    fi
  fi
  
  # Docker
  if systemctl is-active --quiet docker; then
    service_key="docker:N/A"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "docker:N/A" >> "$TMP_SERVICES_FILE" 
      DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker: Running${CL}\n"
      
      # Check for docker containers with exposed ports
      if command -v docker >/dev/null; then
        container_info=$(docker ps --format "{{.Names}}: {{.Ports}}" 2>/dev/null | grep -v "^$" | sort | uniq)
        if [ -n "$container_info" ]; then
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker containers with exposed ports:\n"
          while IFS= read -r line; do
            if [ -n "$line" ]; then
              DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}  - $line\n"
            fi
          done <<< "$container_info"
        fi
      fi
    fi
  fi
  
  # Load detected services into global associative array for firewall rules
  unset DETECTED_SERVICES
  declare -g -A DETECTED_SERVICES
  
  if [ -f "$TMP_SERVICES_FILE" ]; then
    while IFS=: read -r service port; do
      if [ -n "$service" ] && [ -n "$port" ]; then
        DETECTED_SERVICES["$service"]="$port"
      fi
    done < "$TMP_SERVICES_FILE"
    
    # Clean up temp file
    rm -f "$TMP_SERVICES_FILE"
  fi
  
  # If we found services, show them
  if [ -n "$DETECTED_SERVICES_LIST" ]; then
    echo "Detected installed services:"
    echo -e "$DETECTED_SERVICES_LIST"
  else
    echo "No services detected."
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
  
  # Create directory for custom SSH config
  mkdir -p /etc/ssh/sshd_config.d
  
  # Step 1: Check for non-root users before disabling root login
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
  current_user=$(whoami)
  
  if [ "$current_user" = "root" ] && [ -z "$existing_users" ]; then
    msg_error "No non-root users detected. Creating a non-root user is required before disabling root login."
    echo "Would you like to create a non-root user with sudo privileges now?"
    if get_yes_no "Create a non-root sudo user?"; then
      echo -n "Enter username for new sudo user: "
      read -r new_username
      echo
      
      if [ -z "$new_username" ]; then
        msg_error "No username provided. Keeping root login enabled."
      else
        adduser "$new_username"
        usermod -aG sudo "$new_username"
        apt install -y sudo  # Ensure sudo is installed
        msg_ok "User $new_username created with sudo privileges"
        existing_users="$new_username"
      fi
    else
      msg_info "Keeping root login enabled. It's recommended to create a non-root user before disabling root login."
    fi
  fi
  
  # Now check if we can safely disable root login
  if [ "$current_user" != "root" ] || [ -n "$existing_users" ]; then
    if get_yes_no "Disable root SSH login? (Recommended for security)"; then
      echo "PermitRootLogin no" > /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Root SSH login disabled"
      echo "Root SSH login: Disabled" >> "$SUMMARY_FILE"
    else
      msg_info "Root SSH login remains enabled"
      echo "Root SSH login: Enabled" >> "$SUMMARY_FILE"
    fi
  fi
  
  # Step 2: SSH key setup
  echo "Checking for existing SSH keys..."
  
  has_ssh_keys=false
  for user in $existing_users; do
    user_home=$(eval echo ~${user})
    if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
      has_ssh_keys=true
      msg_ok "SSH keys found for user: $user"
    fi
  done
  
  if [ "$has_ssh_keys" = false ]; then
    msg_info "No SSH keys detected for any users"
    
    if get_yes_no "Would you like to set up SSH key authentication? (Recommended)"; then
      while true; do
        setup_ssh_keys
        
        # Check if keys were setup successfully
        for user in $existing_users; do
          user_home=$(eval echo ~${user})
          if [ -f "${user_home}/.ssh/authorized_keys" ] && [ -s "${user_home}/.ssh/authorized_keys" ]; then
            has_ssh_keys=true
            msg_ok "SSH keys verified for user: $user"
            echo "SSH keys: Configured for user $user" >> "$SUMMARY_FILE"
            break
          fi
        done
        
        if [ "$has_ssh_keys" = true ]; then
          break
        else
          if get_yes_no "SSH keys not detected. Would you like to try again?"; then
            continue
          else
            msg_info "Skipping SSH key setup"
            echo "SSH keys: Not configured" >> "$SUMMARY_FILE"
            break
          fi
        fi
      done
    else
      echo "SSH keys: Not configured" >> "$SUMMARY_FILE"
    fi
  else
    echo "SSH keys: Already configured" >> "$SUMMARY_FILE"
  fi
  
  # Step 3: Enable public key authentication
  echo "PubkeyAuthentication yes" >> /etc/ssh/sshd_config.d/50-security.conf
  msg_ok "Public key authentication enabled"
  echo "Public key authentication: Enabled" >> "$SUMMARY_FILE"
  
  # Step 4: Disable password authentication (only if SSH keys are set up)
  if [ "$has_ssh_keys" = true ]; then
    if get_yes_no "SSH keys detected. Would you like to disable password authentication? (Recommended when using SSH keys)"; then
      echo "PasswordAuthentication no" >> /etc/ssh/sshd_config.d/50-security.conf
      msg_ok "Password authentication disabled"
      echo "Password authentication: Disabled" >> "$SUMMARY_FILE"
    else
      msg_info "Password authentication remains enabled"
      echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
    fi
  else
    msg_info "Password authentication remains enabled (SSH keys not detected)"
    echo "Password authentication: Enabled" >> "$SUMMARY_FILE"
  fi
  
  # Step 5: Limit SSH access to specific users
  if get_yes_no "Would you like to limit SSH access to specific users?"; then
    # Get list of non-system users
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
        echo "SSH access limited to: $formatted_users" >> "$SUMMARY_FILE"
      else
        msg_info "No valid users selected"
      fi
    fi
  else
    echo "SSH access: Not limited to specific users" >> "$SUMMARY_FILE"
  fi
  
  # Step 6: Setup passwordless sudo if using SSH keys
  if [ "$has_ssh_keys" = true ]; then
    setup_passwordless_sudo
  fi
  
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
    echo "1. ON YOUR LOCAL MACHINE, first generate an SSH key if you don't already have one: ssh-keygen -t ed25519 -C \"email@example.com\""
    echo
    echo "2. Then copy your key to this server with: ssh-copy-id $username@$(hostname -I | awk '{print $1}')"
    echo
    
    # Set up .ssh directory with correct permissions
    user_home=$(eval echo ~${username})
    mkdir -p ${user_home}/.ssh
    touch ${user_home}/.ssh/authorized_keys
    
    # Fix permissions
    chmod 700 ${user_home}/.ssh
    chmod 600 ${user_home}/.ssh/authorized_keys
    chown -R ${username}:${username} ${user_home}/.ssh
    
    msg_ok "SSH directory created with correct permissions for $username"
    
    echo "Please complete the following steps:"
    echo "1. Keep this terminal window open"
    echo "2. Open a new terminal window on your local machine"
    echo "3. Generate and copy your SSH key as shown above"
    echo "4. Return to this window when complete"
    echo
    
    if get_yes_no "Have you copied your SSH key to the server?"; then
      # Check if key was actually copied
      if [ -s "${user_home}/.ssh/authorized_keys" ]; then
        msg_ok "SSH key detected for $username"
        return 0
      else
        msg_error "No SSH key detected for $username"
        return 1
      fi
    else
      msg_info "You can complete this step later, but some security features will be unavailable until then"
      return 1
    fi
  else
    msg_info "Invalid selection. SSH key setup cancelled."
    return 1
  fi
}

# Function to set up passwordless sudo for SSH users
setup_passwordless_sudo() {
  # Get list of sudo-capable users
  sudo_users=$(grep -Po '^sudo.+:\K.*$' /etc/group 2>/dev/null | tr ',' ' ')
  
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
        echo "Passwordless sudo: Enabled for $username" >> "$SUMMARY_FILE"
      else
        msg_info "Passwordless sudo configuration cancelled"
      fi
    else
      msg_info "Invalid selection. Passwordless sudo configuration cancelled."
    fi
  else
    msg_info "Passwordless sudo configuration skipped"
    echo "Passwordless sudo: Not configured" >> "$SUMMARY_FILE"
  fi
}

#######################
# 2. FIREWALL SETUP
#######################

# Function to optionally configure UFW
configure_firewall() {
  if get_yes_no "Would you like to install and configure UFW (Uncomplicated Firewall)? Note: If you're using a cloud VPS, it might already have a firewall configured at the provider level."; then
    if ! command -v ufw >/dev/null; then
      msg_info "Installing UFW (Uncomplicated Firewall)..."
      apt install -y ufw
    fi
    
    # Check if UFW is already enabled
    ufw_status=$(ufw status | head -1)
    
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
    if [ ${#DETECTED_SERVICES[@]} -gt 0 ]; then
      echo "Detected services with following ports:"
      echo -e "$DETECTED_SERVICES_LIST"
      
      if get_yes_no "Would you like to add firewall rules for these detected services?"; then
        for service in "${!DETECTED_SERVICES[@]}"; do
          ports="${DETECTED_SERVICES[$service]}"
          
          # Skip services with N/A as port or already processed HTTP/HTTPS
          if [ "$ports" = "N/A" ] || [ "$service" = "nginx" ] || [ "$service" = "apache2" ]; then
            continue
          fi
          
          # Add multiple port entries if comma-separated
          IFS=',' read -ra PORT_ARRAY <<< "$ports"
          for port in "${PORT_ARRAY[@]}"; do
            ufw allow "$port"/tcp comment "$service"
            msg_ok "Added rule for $service (Port $port)"
          done
        done
      fi
    fi
    
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
        echo "Firewall (UFW): Enabled" >> "$SUMMARY_FILE"
      else
        msg_info "Firewall configured but not enabled"
        echo "Firewall (UFW): Configured but not enabled" >> "$SUMMARY_FILE"
      fi
    else
      if get_yes_no "Firewall is already active. Do you want to reload the configuration?"; then
        ufw reload
        msg_ok "Firewall configuration reloaded"
        echo "Firewall (UFW): Active and reloaded" >> "$SUMMARY_FILE"
      else
        echo "Firewall (UFW): Active but not reloaded" >> "$SUMMARY_FILE"
      fi
    fi
    
    # Show UFW rules summary
    echo "Current firewall configuration:"
    echo
    ufw status verbose
    echo
  else
    msg_info "UFW configuration skipped"
    echo "Firewall (UFW): Not configured" >> "$SUMMARY_FILE"
    
    # Add detected services to summary for cloud firewall reference
    if [ -n "$DETECTED_SERVICES_LIST" ]; then
      echo "Note: The following services were detected. Please ensure your cloud firewall allows these ports:" >> "$SUMMARY_FILE"
      echo -e "$DETECTED_SERVICES_LIST" >> "$SUMMARY_FILE"
    fi
  fi
}

#######################
# 3. FAIL2BAN SETUP
#######################

# Setup Fail2Ban function with simplified configuration
setup_fail2ban() {
  if get_yes_no "Would you like to install and configure Fail2Ban? It helps protect your server against brute-force attacks."; then
    msg_info "Installing Fail2Ban..."
    apt install -y fail2ban
    
    # Create a local configuration with default settings
    cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
# Ban hosts for 10 minutes (600 seconds)
bantime = 600
# Find time window of 10 minutes
findtime = 600
# Allow 5 retries
maxretry = 5
# Ignore localhost
ignoreip = 127.0.0.1 ::1
EOF
    
    # Ask for IP whitelist
    echo -n "Enter IPs or ranges to whitelist (space-separated, leave empty for none): "
    read -r whitelist_ips
    echo
    
    if [[ -n "$whitelist_ips" ]]; then
      # Append to ignoreip
      sed -i "s/ignoreip = 127.0.0.1 ::1/ignoreip = 127.0.0.1 ::1 $whitelist_ips/" /etc/fail2ban/jail.local
      msg_ok "Added whitelisted IPs: $whitelist_ips"
      echo "Fail2Ban whitelist: $whitelist_ips" >> "$SUMMARY_FILE"
    fi
    
    # Add SSH jail
    cat >> /etc/fail2ban/jail.local << EOF

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF
    
    # Enable and start Fail2Ban
    systemctl enable fail2ban
    systemctl restart fail2ban
    
    msg_ok "Fail2Ban installed and configured with default settings"
    echo "Fail2Ban: Installed and active" >> "$SUMMARY_FILE"
    echo "Fail2Ban settings: bantime=600s, findtime=600s, maxretry=5" >> "$SUMMARY_FILE"
    echo "Fail2Ban command to modify settings: sudo nano /etc/fail2ban/jail.local" >> "$SUMMARY_FILE"
    echo "Fail2Ban command to reload: sudo systemctl reload fail2ban" >> "$SUMMARY_FILE"
    
    # Save command for adding VPN subnet to whitelist for later
    mkdir -p "$TEMP_DIR"
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
    echo "Fail2Ban: Not installed" >> "$SUMMARY_FILE"
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
      echo "VPN: Not configured" >> "$SUMMARY_FILE"
      ;;
    *)
      msg_info "VPN setup skipped"
      echo "VPN: Not configured" >> "$SUMMARY_FILE"
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
    
    if [[ -n "$auth_key" ]]; then
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
    tailscale_ip=$(tailscale ip 2>/dev/null || echo "Unknown")
    tailscale_subnet="100.64.0.0/10"  # Default Tailscale subnet
    
    # Save command for allowing VPN subnet in firewall for later
    mkdir -p "$TEMP_DIR"
    echo "# To allow traffic from the Tailscale VPN subnet in UFW:" > "$TEMP_DIR/vpn_firewall.txt"
    echo "sudo ufw allow from $tailscale_subnet comment 'Tailscale VPN subnet'" >> "$TEMP_DIR/vpn_firewall.txt"
    
    # Save command for Fail2Ban whitelist
    echo "# To add the Tailscale subnet to Fail2Ban whitelist:" >> "$TEMP_DIR/fail2ban_vpn.txt"
    echo "sudo fail2ban-client set sshd addignoreip $tailscale_subnet" >> "$TEMP_DIR/fail2ban_vpn.txt"
    
    echo "Tailscale has been successfully configured."
    echo
    echo -e "Your Tailscale IP: ${HIGHLIGHT}$tailscale_ip${CL}"
    echo -e "Tailscale subnet: ${HIGHLIGHT}$tailscale_subnet${CL}"
    echo
    
    echo "VPN: Tailscale" >> "$SUMMARY_FILE"
    echo "Tailscale IP: $tailscale_ip" >> "$SUMMARY_FILE"
    echo "Tailscale subnet: $tailscale_subnet" >> "$SUMMARY_FILE"
  else
    msg_error "Tailscale installation failed"
    echo "VPN: Tailscale installation failed" >> "$SUMMARY_FILE"
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
    
    if [[ -n "$setup_key" ]]; then
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
      echo "sudo ufw allow from $netbird_subnet comment 'Netbird VPN subnet'" >> "$TEMP_DIR/vpn_firewall.txt"
      
      # Save command for Fail2Ban whitelist
      echo "# To add the Netbird subnet to Fail2Ban whitelist:" >> "$TEMP_DIR/fail2ban_vpn.txt"
      echo "sudo fail2ban-client set sshd addignoreip $netbird_subnet" >> "$TEMP_DIR/fail2ban_vpn.txt"
      
      echo "Netbird has been successfully configured."
      echo
      echo -e "Your Netbird IP: ${HIGHLIGHT}$netbird_ip${CL}"
      echo -e "Netbird subnet: ${HIGHLIGHT}$netbird_subnet${CL}"
      echo
      
      echo "VPN: Netbird" >> "$SUMMARY_FILE"
      echo "Netbird IP: $netbird_ip" >> "$SUMMARY_FILE"
      echo "Netbird subnet: $netbird_subnet" >> "$SUMMARY_FILE"
    else
      msg_error "Netbird setup key not provided"
      echo "VPN: Netbird configuration failed (no setup key)" >> "$SUMMARY_FILE"
    fi
  else
    msg_error "Netbird installation failed"
    echo "VPN: Netbird installation failed" >> "$SUMMARY_FILE"
  fi
}

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
    
    # Disable automatic reboot in configuration
    sed -i "s|^Unattended-Upgrade::Automatic-Reboot \".*\";|Unattended-Upgrade::Automatic-Reboot \"false\";|" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
    if ! grep -q "Unattended-Upgrade::Automatic-Reboot" /etc/apt/apt.conf.d/50unattended-upgrades; then
      echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    fi
    
    # Restart unattended-upgrades service
    systemctl restart unattended-upgrades
    
    msg_ok "Automatic security updates configured successfully (no automatic reboot)"
    echo "Automatic security updates: Enabled" >> "$SUMMARY_FILE"
    echo "Automatic reboot: Disabled" >> "$SUMMARY_FILE"
  else
    msg_info "Automatic security updates not configured"
    echo "Automatic security updates: Not configured" >> "$SUMMARY_FILE"
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
  echo "• OS: $(lsb_release -ds 2>/dev/null || cat /etc/debian_version 2>/dev/null || echo "Debian-based")"
  echo
  
  # Read from summary file
  echo "Security Configuration:"
  while IFS= read -r line; do
    echo "• $line"
  done < "$SUMMARY_FILE"
  
  echo
  
  # Add VPN firewall commands if available
  if [ -f "$TEMP_DIR/vpn_firewall.txt" ]; then
    echo "=== VPN Firewall Commands ==="
    cat "$TEMP_DIR/vpn_firewall.txt"
    echo
  fi
  
  # Add Fail2Ban VPN whitelist commands if available
  if [ -f "$TEMP_DIR/fail2ban_vpn.txt" ]; then
    echo "=== Fail2Ban VPN Whitelist Commands ==="
    cat "$TEMP_DIR/fail2ban_vpn.txt"
    echo
  fi
  
  # Save complete summary to file
  summary_file="/root/debian-express-security-summary.txt"
  
  {
    echo "=== Debian Express Security Summary ==="
    echo
    echo "System Information:"
    echo "• Hostname: $(hostname)"
    echo "• IP Address: $server_ip"
    echo "• OS: $(lsb_release -ds 2>/dev/null || cat /etc/debian_version 2>/dev/null || echo "Debian-based")"
    echo
    echo "Security Configuration:"
    while IFS= read -r line; do
      echo "• $line"
    done < "$SUMMARY_FILE"
    echo
    
    # Add VPN firewall commands if available
    if [ -f "$TEMP_DIR/vpn_firewall.txt" ]; then
      echo "=== VPN Firewall Commands ==="
      cat "$TEMP_DIR/vpn_firewall.txt"
      echo
    fi
    
    # Add Fail2Ban VPN whitelist commands if available
    if [ -f "$TEMP_DIR/fail2ban_vpn.txt" ]; then
      echo "=== Fail2Ban VPN Whitelist Commands ==="
      cat "$TEMP_DIR/fail2ban_vpn.txt"
      echo
    fi
  } > "$summary_file"
  
  chmod 600 "$summary_file"
  
  echo "Complete security summary saved to: $summary_file"
  echo
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
  if get_yes_no "Would you like to reboot now?"; then
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
  
  # Detect installed services
  detect_services
  
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
