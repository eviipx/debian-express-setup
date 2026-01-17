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

# Cache system information (populated in main function)
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

# Function to get yes/no input from user - FIXED to prevent syntax errors
get_yes_no() {
  local prompt="$1"
  local response
  
  while true; do
    # Fixed line to escape parentheses properly
    echo -e -n "${prompt} [${HIGHLIGHT}y${CL}/${HIGHLIGHT}n${CL}]: "
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

# Detect OS version and display it (sets global variables)
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

# Cache server IP address
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

    # Validate IP octets
    IFS='.' read -ra OCTETS <<< "$ip"
    for octet in "${OCTETS[@]}"; do
      if [ "$octet" -gt 255 ]; then
        return 1
      fi
    done

    # Validate CIDR range (0-32)
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
  FULL_SERVICES_LIST=""

  # Track services we've already seen to prevent duplicates
  declare -A seen_services

  # Read from the state file created by the setup script (if it exists)
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

        # Improve display for Docker API
        if [ "$service" = "docker" ] && [ "$port" = "2375" ]; then
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker API: Port ${HIGHLIGHT}${port}${CL} (unencrypted remote access)\n"
        else
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• ${service^}: Port ${HIGHLIGHT}${port}${CL}\n"
        fi
      fi
    done < "$STATE_FILE"
  fi

  # Detect Docker and Docker API configuration
  if command -v docker >/dev/null && systemctl is-active --quiet docker; then
    # Check if Docker API is exposed
    if [ -f /etc/docker/daemon.json ]; then
      if grep -q '"hosts"' /etc/docker/daemon.json; then
        if grep -q "tcp://0.0.0.0:2375" /etc/docker/daemon.json; then
          service_key="docker:2375"
          if [ -z "${seen_services[$service_key]}" ]; then
            seen_services["$service_key"]=1
            echo "docker:2375" >> "$TMP_SERVICES_FILE"
            DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker API: Port ${HIGHLIGHT}2375${CL} (unencrypted remote access)\n"
          fi
        fi
      fi
    fi

    # Check systemd Docker service for exposed API
    if systemctl cat docker.service 2>/dev/null | grep -q -- "-H tcp://0.0.0.0:2375"; then
      service_key="docker:2375"
      if [ -z "${seen_services[$service_key]}" ]; then
        seen_services["$service_key"]=1
        echo "docker:2375" >> "$TMP_SERVICES_FILE"
        DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker API: Port ${HIGHLIGHT}2375${CL} (unencrypted remote access)\n"
      fi
    fi

    # We no longer display "Docker: Running" in the simplified output
    # But we do keep it for the firewall rules
    service_key="docker:N/A"
    if [ -z "${seen_services[$service_key]}" ]; then
      seen_services["$service_key"]=1
      echo "docker:N/A" >> "$TMP_SERVICES_FILE"
      FULL_SERVICES_LIST="${FULL_SERVICES_LIST}• Docker: Running${CL}\n"
    fi

    # Detect Docker containers with exposed ports but don't display in the main list
    container_info=$(docker ps --format "{{.Names}}|{{.Ports}}" 2>/dev/null | grep -v "^$" | sort | uniq)
    if [ -n "$container_info" ]; then
      FULL_SERVICES_LIST="${FULL_SERVICES_LIST}• Docker containers with exposed ports:\n"

      # Process each container and detect known services for direct display
      while IFS="|" read -r container_name ports; do
        # Add container details to full list but not simplified list
        formatted_ports=$(echo "$ports" | tr -s ' ' | sed 's/,/,\n    /g')
        FULL_SERVICES_LIST="${FULL_SERVICES_LIST}  - $container_name: $formatted_ports\n"

        # Check for known containers and their ports - these go in the simplified list
        if echo "$container_name" | grep -q "dockge"; then
          # Extract Dockge port(s)
          dockge_ports=$(echo "$ports" | grep -o "[0-9]\+->5001/tcp" | cut -d'-' -f1 | tr -d ':' | tr -d '>')
          for port in $dockge_ports; do
            service_key="dockge:$port"
            if [ -z "${seen_services[$service_key]}" ]; then
              seen_services["$service_key"]=1
              echo "dockge:$port" >> "$TMP_SERVICES_FILE"
              DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Dockge: Port ${HIGHLIGHT}${port}${CL}\n"
            fi
          done
        fi

        # For Traefik, only display the ports it's running on
        if echo "$container_name" | grep -q "traefik"; then
          # Extract Traefik port(s)
          http_port=$(echo "$ports" | grep -o "[0-9]\+->80/tcp" | cut -d'-' -f1 | tr -d ':' | tr -d '>')
          https_port=$(echo "$ports" | grep -o "[0-9]\+->443/tcp" | cut -d'-' -f1 | tr -d ':' | tr -d '>')

          if [ -n "$http_port" ] || [ -n "$https_port" ]; then
            traefik_ports=""
            [ -n "$http_port" ] && traefik_ports="$http_port"
            [ -n "$https_port" ] && traefik_ports="${traefik_ports:+$traefik_ports,}$https_port"

            service_key="traefik:$traefik_ports"
            if [ -z "${seen_services[$service_key]}" ]; then
              seen_services["$service_key"]=1
              echo "traefik:$traefik_ports" >> "$TMP_SERVICES_FILE"
              DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Traefik: Ports ${HIGHLIGHT}${traefik_ports}${CL}\n"
            fi
          fi
        fi
      done <<< "$container_info"
    fi
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

  # Save full service list for the summary file
  FULL_SERVICES_INFO="$DETECTED_SERVICES_LIST"
  if [ -n "$FULL_SERVICES_LIST" ]; then
    FULL_SERVICES_INFO="$FULL_SERVICES_INFO\nDetailed container information:\n$FULL_SERVICES_LIST"
  fi

  # If we found services, show only the simplified list
  if [ -n "$DETECTED_SERVICES_LIST" ]; then
    echo "Detected installed services:"
    echo -e "$DETECTED_SERVICES_LIST"

    # Save full list to a file for reference in the summary
    echo -e "$FULL_SERVICES_INFO" > "$TEMP_DIR/full_services.txt"
  else
    echo "No services detected."
  fi
}

#######################
# 2. FIREWALL SETUP
#######################

# Function to configure UFW firewall
configure_firewall() {
  if get_yes_no "Would you like to install and configure UFW (Uncomplicated Firewall)?"; then
    if ! command -v ufw >/dev/null; then
      msg_info "Installing UFW (Uncomplicated Firewall)..."
      apt install -y ufw
    fi

    # Check if UFW is already enabled
    ufw_status=$(ufw status | head -1)

    # Configure basic rules
    if get_yes_no "Do you want to apply the recommended basic rules? (Allow SSH, deny incoming, allow outgoing)"; then
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

    # Ask about custom ports
    if get_yes_no "Do you want to allow any custom ports?"; then
      while true; do
        echo -n "Enter port number to allow (1-65535): "
        read -r port
        echo

        if [[ -z "$port" ]]; then
          break
        fi

        if validate_port "$port"; then
          echo "Select protocol:"
          echo -e "${HIGHLIGHT}1${CL}) TCP only"
          echo -e "${HIGHLIGHT}2${CL}) UDP only"
          echo -e "${HIGHLIGHT}3${CL}) Both TCP and UDP"
          echo
          echo -n "Enter your selection [1-3]: "
          read -r proto_selection
          echo

          echo -n "Enter a description for this rule: "
          read -r description
          echo

          # Set up firewall rules based on protocol selection
          if [ "$proto_selection" = "1" ]; then
            ufw allow "$port"/tcp comment "$description"
            msg_ok "Port $port/tcp allowed: $description"
          elif [ "$proto_selection" = "2" ]; then
            ufw allow "$port"/udp comment "$description"
            msg_ok "Port $port/udp allowed: $description"
          else
            ufw allow "$port" comment "$description"
            msg_ok "Port $port (tcp & udp) allowed: $description"
          fi
        else
          msg_error "Invalid port number. Please enter a valid port between 1 and 65535."
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
    
    # Ask for IP whitelist with better formatting and examples
    echo "Enter IPs or ranges to whitelist (space-separated, leave empty for none):"
    echo "Examples: 192.168.1.5  10.0.0.0/24  192.168.0.0/16"
    echo
    echo -n "> "
    read -r whitelist_ips
    echo

    if [[ -n "$whitelist_ips" ]]; then
      # Validate each IP/CIDR
      valid_ips=""
      invalid_count=0
      for ip in $whitelist_ips; do
        if validate_ip_or_cidr "$ip"; then
          valid_ips="$valid_ips $ip"
        else
          msg_error "Invalid IP or CIDR: $ip (skipped)"
          ((invalid_count++))
        fi
      done

      if [[ -n "$valid_ips" ]]; then
        # Append to ignoreip
        sed -i "s|ignoreip = 127.0.0.1 ::1|ignoreip = 127.0.0.1 ::1$valid_ips|" /etc/fail2ban/jail.local
        msg_ok "Added whitelisted IPs:$valid_ips"
        echo "Fail2Ban whitelist:$valid_ips" >> "$SUMMARY_FILE"
      fi

      if [ $invalid_count -gt 0 ]; then
        msg_info "$invalid_count invalid IP/CIDR entries were skipped"
      fi
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
    
    # Wait a moment for the service to fully start
    echo "Waiting for Fail2Ban service to fully start..."
    sleep 3
    
    # Check service status
    if systemctl is-active --quiet fail2ban; then
      echo "Fail2Ban status:"
      echo
      fail2ban-client status sshd 2>/dev/null || echo "Fail2Ban is starting up. Run 'sudo fail2ban-client status sshd' later to check status."
      echo
    else
      echo "Fail2Ban status: Service is starting up."
      echo "Run 'sudo systemctl status fail2ban' later to verify it's running properly."
      echo
    fi
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
  echo -e "${HIGHLIGHT}1${CL}) Tailscale"
  echo -e "${HIGHLIGHT}2${CL}) Netbird"
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

# Setup Netbird function with improved IP detection
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
      
      # Get Netbird IP with improved detection
      sleep 2 # Give time for interface to come up
      
      # Try multiple ways to detect the Netbird interface and IP
      netbird_ip="Unknown"
      # First try the standard interface name
      if ip addr show netbird0 2>/dev/null | grep -q "inet "; then
        netbird_ip=$(ip addr show netbird0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "Unknown")
      # If that fails, try with netbird command
      elif command -v netbird >/dev/null; then
        netbird_status=$(netbird status 2>/dev/null)
        if [[ $? -eq 0 ]]; then
          netbird_ip=$(echo "$netbird_status" | grep -oP 'IP:\s*\K[0-9.]+' || echo "Unknown")
        fi
      # If all else fails, try to find any interface that might be netbird
      else
        for iface in $(ip -o link | awk -F': ' '{print $2}' | grep -E 'netbird|nb'); do
          if ip addr show "$iface" 2>/dev/null | grep -q "inet "; then
            netbird_ip=$(ip addr show "$iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "Unknown")
            break
          fi
        done
      fi
      
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
    
    # Disable automatic reboot in configuration (but don't mention it in summary)
    sed -i "s|^Unattended-Upgrade::Automatic-Reboot \".*\";|Unattended-Upgrade::Automatic-Reboot \"false\";|" /etc/apt/apt.conf.d/50unattended-upgrades 2>/dev/null
    if ! grep -q "Unattended-Upgrade::Automatic-Reboot" /etc/apt/apt.conf.d/50unattended-upgrades; then
      echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
    fi
    
    # Restart unattended-upgrades service
    systemctl restart unattended-upgrades
    
    msg_ok "Automatic security updates configured successfully"
    echo "Automatic security updates: Enabled" >> "$SUMMARY_FILE"
    # Removed the reboot line from the summary
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
  # Use cached server IP
  cache_server_ip
  
  echo
  echo "=== Debian Express Security Summary ==="
  echo
  echo "System Information:"
  echo "• Hostname: ${HIGHLIGHT}$(hostname)${CL}"
  echo "• IP Address: ${HIGHLIGHT}$SERVER_IP${CL}"
  echo "• OS: ${HIGHLIGHT}$OS_PRETTY${CL}"
  echo
  
  # Organize summary into sections
  echo "SSH Configuration:"
  grep -E "Root SSH|SSH keys|Public key|Password auth|SSH access" "$SUMMARY_FILE" | while IFS= read -r line; do
    key=$(echo "$line" | cut -d':' -f1)
    value=$(echo "$line" | cut -d':' -f2-)
    echo "• $key: ${HIGHLIGHT}$value${CL}"
  done
  echo
  
  # Sudo Configuration
  if grep -q "Passwordless sudo" "$SUMMARY_FILE"; then
    echo "Sudo Configuration:"
    grep "Passwordless sudo" "$SUMMARY_FILE" | while IFS= read -r line; do
      key=$(echo "$line" | cut -d':' -f1)
      value=$(echo "$line" | cut -d':' -f2-)
      echo "• $key: ${HIGHLIGHT}$value${CL}"
    done
    echo
  fi
  
  # Firewall Configuration
  echo "Firewall Configuration:"
  grep -E "^Firewall \(UFW\)" "$SUMMARY_FILE" | while IFS= read -r line; do
    key=$(echo "$line" | cut -d':' -f1)
    value=$(echo "$line" | cut -d':' -f2-)
    echo "• $key: ${HIGHLIGHT}$value${CL}"
  done
  echo
  
  # Detected Services
  echo "Detected Services:"
  if [ -f "$TEMP_DIR/full_services.txt" ]; then
    # Use our simplified service list if available
    while IFS= read -r line; do
      if [[ "$line" != *"Docker containers with exposed ports"* && "$line" != *"  - "* ]]; then
        echo "• $line"
      fi
    done < "$TEMP_DIR/full_services.txt"
  elif grep -q "Note: The following services were detected" "$SUMMARY_FILE"; then
    # Fall back to summary file if needed
    in_services_section=false
    while IFS= read -r line; do
      if [[ "$in_services_section" == true ]]; then
        if [[ "$line" == "• Fail2Ban"* ]]; then
          in_services_section=false
          continue
        fi
        if [[ "$line" != *"Docker containers with exposed ports"* && "$line" != *"  - "* ]]; then
          echo "$line"
        fi
      fi
      if [[ "$line" == "• Note: The following services were detected"* ]]; then
        in_services_section=true
      fi
    done < "$SUMMARY_FILE"
  fi
  echo
  
  # Fail2Ban Configuration
  echo "Fail2Ban Configuration:"
  grep -E "^Fail2Ban" "$SUMMARY_FILE" | while IFS= read -r line; do
    key=$(echo "$line" | cut -d':' -f1)
    value=$(echo "$line" | cut -d':' -f2-)
    echo "• $key: ${HIGHLIGHT}$value${CL}"
  done
  echo
  
  # VPN Configuration
  if grep -q "^VPN:" "$SUMMARY_FILE"; then
    echo "VPN Configuration:"
    grep -E "^VPN:|^Netbird|^Tailscale" "$SUMMARY_FILE" | while IFS= read -r line; do
      key=$(echo "$line" | cut -d':' -f1)
      value=$(echo "$line" | cut -d':' -f2-)
      echo "• $key: ${HIGHLIGHT}$value${CL}"
    done
    echo
  fi
  
  # Update Configuration
  echo "Update Configuration:"
  grep "Automatic security updates" "$SUMMARY_FILE" | while IFS= read -r line; do
    key=$(echo "$line" | cut -d':' -f1)
    value=$(echo "$line" | cut -d':' -f2-)
    echo "• $key: ${HIGHLIGHT}$value${CL}"
  done
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
  
  # Save complete summary to file with the same improvements
  summary_file="/root/debian-express-security-summary.txt"
  
  {
    echo "=== Debian Express Security Summary ==="
    echo
    echo "System Information:"
    echo "• Hostname: $(hostname)"
    echo "• IP Address: $SERVER_IP"
    echo "• OS: $OS_PRETTY"
    echo
    
    # Organized sections in the file (without colors)
    echo "SSH Configuration:"
    grep -E "Root SSH|SSH keys|Public key|Password auth|SSH access" "$SUMMARY_FILE" | while IFS= read -r line; do
      echo "• $line"
    done
    echo
    
    if grep -q "Passwordless sudo" "$SUMMARY_FILE"; then
      echo "Sudo Configuration:"
      grep "Passwordless sudo" "$SUMMARY_FILE" | while IFS= read -r line; do
        echo "• $line"
      done
      echo
    fi
    
    echo "Firewall Configuration:"
    grep -E "^Firewall \(UFW\)" "$SUMMARY_FILE" | while IFS= read -r line; do
      echo "• $line"
    done
    echo
    
    echo "Detected Services:"
    if [ -f "$TEMP_DIR/full_services.txt" ]; then
      while IFS= read -r line; do
        if [[ "$line" != *"Docker containers with exposed ports"* && "$line" != *"  - "* ]]; then
          echo "• $line"
        fi
      done < "$TEMP_DIR/full_services.txt"
    elif grep -q "Note: The following services were detected" "$SUMMARY_FILE"; then
      in_services_section=false
      while IFS= read -r line; do
        if [[ "$in_services_section" == true ]]; then
          if [[ "$line" == "• Fail2Ban"* ]]; then
            in_services_section=false
            continue
          fi
          if [[ "$line" != *"Docker containers with exposed ports"* && "$line" != *"  - "* ]]; then
            echo "$line"
          fi
        fi
        if [[ "$line" == "• Note: The following services were detected"* ]]; then
          in_services_section=true
        fi
      done < "$SUMMARY_FILE"
    fi
    echo
    
    echo "Fail2Ban Configuration:"
    grep -E "^Fail2Ban" "$SUMMARY_FILE" | while IFS= read -r line; do
      echo "• $line"
    done
    echo
    
    if grep -q "^VPN:" "$SUMMARY_FILE"; then
      echo "VPN Configuration:"
      grep -E "^VPN:|^Netbird|^Tailscale" "$SUMMARY_FILE" | while IFS= read -r line; do
        echo "• $line"
      done
      echo
    fi
    
    echo "Update Configuration:"
    grep "Automatic security updates" "$SUMMARY_FILE" | while IFS= read -r line; do
      echo "• $line"
    done
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
  
  # Clean up state file to ensure fresh detection on next run
  if [ -f "$STATE_FILE" ]; then
    rm -f "$STATE_FILE"
    msg_ok "State file cleaned up for fresh detection on next run"
  fi
  
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
  cache_server_ip  # Cache server IP for use throughout script
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
