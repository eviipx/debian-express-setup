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

# Function to get yes/no input from user - FIXED to prevent syntax errors
get_yes_no() {
  local prompt="$1"
  local response
  
  while true; do
    # Fixed line to escape parentheses properly
    echo -e -n "${prompt} [${HIGHLIGHT}y${CL}/${HIGHLIGHT}n${CL}]: "
    read -r response
    case $response in
      [Yy]* ) return 0 ;;
      [Nn]* ) return 1 ;;
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

# Detect services function
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
        echo "Firewall (UFW): Active but not reloaded" >> "$SUMMARY_FILE"
        
        # Add to services file and detected list
        echo "$service:$port" >> "$TMP_SERVICES_FILE"
        
        # Improve display for Docker API
        if [ "$service" = "docker" ] && [ "$port" = "2375" ]; then
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• Docker API: Port ${HIGHLIGHT}${port}${CL} (unencrypted remote access)\n"
        else
          DETECTED_SERVICES_LIST="${DETECTED_SERVICES_LIST}• ${service^}: Port ${HIGHLIGHT}${port}${CL}\n"
        fi
      fi
    done < "$STATE_FILE"
  else
    echo "Firewall (UFW): Not configured" >> "$SUMMARY_FILE"
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
  
  # If we found services, show the list
  if [ -n "$DETECTED_SERVICES_LIST" ]; then
    echo "Detected installed services:"
    echo -e "$DETECTED_SERVICES_LIST"
  else
    echo "No services detected."
  fi
}

# Function to configure SSH and security settings
configure_ssh_security() {
  msg_info "Configuring SSH and security settings..."
  
  # Pre-existing SSH configuration logic
  # ... (rest of the function remains the same as in the original script)
}

# Function to add VPN firewall rules
add_vpn_firewall_rules() {
  # Check if VPN configuration files exist
  if [ -f "$TEMP_DIR/vpn_firewall.txt" ]; then
    vpn_firewall_rules=$(cat "$TEMP_DIR/vpn_firewall.txt")
    
    if [ -n "$vpn_firewall_rules" ]; then
      if get_yes_no "Add VPN subnet rules to firewall?"; then
        # Execute the VPN firewall commands
        bash -c "$vpn_firewall_rules"
        msg_ok "VPN firewall rules added"
      fi
    fi
  fi
}

###################
# MAIN FUNCTION
###################
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
  
  # Set up firewall
  configure_firewall
  
  # Add VPN firewall rules if VPN was configured
  add_vpn_firewall_rules
  
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
