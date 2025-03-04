#!/usr/bin/env bash

# Debian Express Setup
# System Setup & Optimization Script
# Author: [Your Name]
# License: MIT
# Description: Sets up and optimizes Debian-based servers with essential tools

# Define colors and formatting with better contrast
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

# Flag to track if Docker has been installed
DOCKER_INSTALLED=false

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

# Record installed service for the security script to find
record_installed_service() {
  local service="$1"
  local port="$2"
  echo "$service:$port" >> "$STATE_FILE"
  msg_info "Recorded $service (port $port) for firewall configuration"
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
EOF

  echo -e "\n${BL}System Setup & Optimization${CL}\n"
}

#########################
# 1. CORE CONFIGURATION #
#########################

# Function to update and upgrade the system
update_system() {
  if get_yes_no "Do you want to update and upgrade system packages?"; then
    msg_info "Updating and upgrading system packages..."
    apt update && apt upgrade -y
    msg_ok "System packages updated and upgraded"
  else
    msg_info "Skipping system update"
  fi
}

# Function to set hostname
configure_hostname() {
  current_hostname=$(hostname)
  echo -e "Current hostname: ${HIGHLIGHT}$current_hostname${CL}"
  echo -n "Enter new hostname (leave empty to keep current): "
  read -r new_hostname
  echo
  
  if [ -n "$new_hostname" ] && [ "$new_hostname" != "$current_hostname" ]; then
    hostnamectl set-hostname "$new_hostname"
    # Update /etc/hosts file
    sed -i "s/127.0.1.1.*$current_hostname/127.0.1.1\t$new_hostname/g" /etc/hosts
    msg_ok "Hostname changed to $new_hostname"
  else
    msg_info "Hostname unchanged"
  fi
}

# Function to set timezone
configure_timezone() {
  current_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
  echo -e "Current timezone: ${HIGHLIGHT}$current_timezone${CL}"
  if get_yes_no "Do you want to change the timezone?"; then
    dpkg-reconfigure tzdata
    new_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    msg_ok "Timezone set to $new_timezone"
  else
    msg_info "Timezone unchanged"
  fi
}

# Function to configure locale
configure_locale() {
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

  echo -e "Current locale: ${HIGHLIGHT}$readable_locale${CL}"
  if get_yes_no "Do you want to configure system locale?"; then
    dpkg-reconfigure locales
    new_locale=$(locale | grep LANG= | cut -d= -f2)
    msg_ok "Locale set to $new_locale"
  else
    msg_info "Locale unchanged"
  fi
}

# Function to manage root password
configure_root_password() {
  if get_yes_no "Do you want to set/change the root password?"; then
    passwd root
    echo
    msg_ok "Root password updated"
  else
    msg_info "Root password unchanged"
  fi
}

# Function to create non-root user
configure_user() {
  # Get list of non-system users
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort | tr '\n' ' ')
  if [ -z "$existing_users" ]; then
    existing_users="None"
  fi

  echo -e "Current non-system users: ${HIGHLIGHT}$existing_users${CL}"
  if get_yes_no "Do you want to create a new non-root user with sudo access?"; then
    echo -n "Enter username for the new user: "
    read -r username
    echo
    
    if [ -n "$username" ]; then
      # Check if user already exists
      if id "$username" &>/dev/null; then
        if get_yes_no "User $username already exists. Do you want to modify this user instead?"; then
          # Continue with modification options
          msg_info "Proceeding with user modification"
        else
          msg_info "User creation/modification skipped"
          return
        fi
      else
        adduser "$username"
        echo
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
}

########################
# 2. SYSTEM OPTIMIZATION
########################

# Function to optimize system parameters
optimize_system() {
  if get_yes_no "Would you like to apply system optimizations?"; then
    # Call each optimization function
    configure_swap
    install_nohang # Moved up in the flow as requested
    optimize_io_scheduler
    optimize_kernel_parameters
    
    msg_ok "System optimization completed"
  else
    msg_info "System optimization skipped"
  fi
}

# Function to configure swap based on RAM
configure_swap() {
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
    echo -e "Current swap: ${HIGHLIGHT}${swap_size}MB${CL}, RAM: ${HIGHLIGHT}${ram_size}MB${CL}"
    echo -e "Recommended swap: ${HIGHLIGHT}${recommended_swap}MB${CL}"
    echo
    echo "What would you like to do?"
    echo -e "${HIGHLIGHT}1${CL}) Keep current swap configuration"
    echo -e "${HIGHLIGHT}2${CL}) Resize swap to recommended size (${recommended_swap}MB)"
    echo -e "${HIGHLIGHT}3${CL}) Set a custom swap size"
    echo
    echo -n "Enter option [1-3]: "
    read -r swap_option
    echo
    
    case $swap_option in
      1)
        msg_info "Keeping current swap configuration"
        ;;
      2)
        # Turn off existing swap
        swapoff -a
        # Resize the swap file
        create_swap_file "${recommended_swap}"
        ;;
      3)
        echo -n "Enter desired swap size in MB: "
        read -r custom_size
        echo
        if [ -n "$custom_size" ]; then
          swapoff -a
          create_swap_file "${custom_size}"
        else
          msg_info "Swap configuration unchanged"
        fi
        ;;
      *)
        msg_info "Invalid option. Swap configuration unchanged"
        ;;
    esac
  else
    echo -e "No swap detected, RAM: ${HIGHLIGHT}${ram_size}MB${CL}"
    echo -e "Recommended swap: ${HIGHLIGHT}${recommended_swap}MB${CL}"
    echo
    echo "What would you like to do?"
    echo -e "${HIGHLIGHT}1${CL}) Create swap with recommended size (${recommended_swap}MB)"
    echo -e "${HIGHLIGHT}2${CL}) Create swap with custom size"
    echo -e "${HIGHLIGHT}3${CL}) Do not create swap"
    echo
    echo -n "Enter option [1-3]: "
    read -r swap_option
    echo
    
    case $swap_option in
      1)
        create_swap_file "${recommended_swap}"
        ;;
      2)
        echo -n "Enter desired swap size in MB: "
        read -r custom_size
        echo
        if [ -n "$custom_size" ]; then
          create_swap_file "${custom_size}"
        else
          msg_info "Swap configuration unchanged"
        fi
        ;;
      3)
        msg_info "No swap will be created"
        ;;
      *)
        msg_info "Invalid option. No swap will be created"
        ;;
    esac
  fi
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

# Function to install nohang to prevent system freezes (moved up in flow)
install_nohang() {
  if get_yes_no "Would you like to install nohang? It's a daemon that prevents system freezes caused by out-of-memory conditions."; then
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
}

# Function to optimize IO scheduler
optimize_io_scheduler() {
  if get_yes_no "Would you like to optimize the I/O scheduler? This can improve disk performance, especially for SSDs."; then
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
  else
    msg_info "I/O scheduler optimization skipped"
  fi
}

# Function to optimize kernel parameters
optimize_kernel_parameters() {
  if get_yes_no "Would you like to optimize kernel parameters? This can improve system performance and network responsiveness."; then
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
  else
    msg_info "Kernel parameter optimization skipped"
  fi
}

###################################
# 3. MANAGEMENT & MONITORING TOOLS
###################################

# Function to set up monitoring and management tools
setup_monitoring_tools() {
  if get_yes_no "Would you like to install a set of tools for system information, monitoring, and internet speed testing?"; then
    msg_info "Installing system monitoring and utility tools..."
    
    echo "Installing system monitoring tools..."
    
    # Install fastfetch
    add-apt-repository ppa:zhangsongcui3371/fastfetch -y
    apt update
    apt install -y fastfetch
    echo -e "${CM} Fastfetch - System information display"
    
    # Install btop
    apt install -y btop
    echo -e "${CM} Btop - Modern resource monitor"
    
    # Install speedtest-cli
    apt install -y speedtest-cli
    echo -e "${CM} Speedtest-cli - Internet speed test"
    echo
    
    msg_ok "System monitoring tools installed successfully"
  else
    msg_info "System monitoring tools installation skipped"
  fi
}

###########################
# 4. CONTAINER MANAGEMENT #
###########################

# Function to set up Docker and container tools
setup_containers() {
  if get_yes_no "Would you like to set up Docker container management?"; then
    msg_info "Setting up container management..."
    
    # Docker installation
    setup_docker
    
    # Dockge (container manager) installation
    setup_dockge
    
    msg_ok "Container management setup completed"
  else
    msg_info "Container management setup skipped"
  fi
}

# Function to set up Docker
setup_docker() {
  if ! command -v docker >/dev/null; then
    msg_info "Installing Docker..."
    
    # Install Docker using the official script
    curl -fsSL https://get.docker.com | sh
    
    if [[ $? -eq 0 ]]; then
      # Create docker group and add current non-root user if exists
      groupadd -f docker
      
      # Get list of non-system users
      users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)
      
      if [ -n "$users" ]; then
        echo "Select users to add to the docker group (allows running Docker without sudo):"
        echo
        PS3="Enter number or 'done' when finished: "
        select user in $users "done"; do
          if [ "$user" = "done" ]; then
            echo
            break
          elif [ -n "$user" ]; then
            usermod -aG docker "$user"
            echo "Added user $user to the docker group"
          fi
        done
      fi
      
      # Enable and start Docker service
      systemctl enable --now docker
      
      # Install Docker Compose plugin
      apt install -y docker-compose-plugin
      
      msg_ok "Docker installed successfully"
      
      # Record docker service
      record_installed_service "docker" "2375"
      
      # Mark Docker as installed
      DOCKER_INSTALLED=true
    else
      msg_error "Docker installation failed"
    fi
  else
    msg_info "Docker already installed"
    DOCKER_INSTALLED=true
  fi
}

# Function to set up Dockge (container manager)
setup_dockge() {
  # Only offer Dockge if Docker is installed
  if command -v docker >/dev/null; then
    if get_yes_no "Would you like to install Dockge container manager? It's a modern UI for managing Docker Compose stacks."; then
      msg_info "Installing Dockge..."
      
      # Create directory structure
      mkdir -p /opt/stacks/dockge/data
      cd /opt/stacks/dockge
      
      # Download docker-compose.yml - Fixed URL using GitHub content URL
      curl -fsSL https://raw.githubusercontent.com/louislam/dockge/master/compose.yaml -o docker-compose.yml
      
      # If the above URL fails, try the alternate URL
      if [ ! -f docker-compose.yml ] || [ ! -s docker-compose.yml ]; then
        curl -fsSL https://raw.githubusercontent.com/louislam/dockge/master/docker-compose.yml -o docker-compose.yml
      fi
      
      # Start Dockge without setting admin password (let the UI handle first-time setup)
      docker compose up -d
      
      if [[ $? -eq 0 ]]; then
        # Get server IP
        server_ip=$(hostname -I | awk '{print $1}')
        dockge_port=5001
        
        # Record for firewall configuration
        record_installed_service "dockge" "$dockge_port"
        
        echo "Dockge container manager has been installed successfully."
        echo "Access URL: http://$server_ip:$dockge_port"
        echo "Follow the on-screen instructions to create an admin account during first login."
        echo
        
        msg_ok "Dockge installed successfully"
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

#########################
# SUMMARY AND COMPLETION
#########################

# Function to display system information summary
display_summary() {
  # Get server IP
  server_ip=$(hostname -I | awk '{print $1}')
  
  echo
  echo "=== Debian Express Setup Summary ==="
  echo
  echo "System Information:"
  echo "• Hostname: $(hostname)"
  echo "• IP Address: $server_ip"
  echo "• OS: $(lsb_release -ds)"
  echo
  
  # Swap status
  swap_size=$(free -h | grep Swap | awk '{print $2}')
  echo "• Swap: $swap_size"
  
  # System optimization status
  if [ -f /etc/sysctl.d/99-performance.conf ]; then
    echo "• System optimizations: Applied"
  else
    echo "• System optimizations: Not applied"
  fi
  
  # I/O scheduler status
  if [ -f /etc/udev/rules.d/60-scheduler.rules ]; then
    echo "• I/O scheduler: Optimized"
  else
    echo "• I/O scheduler: Default"
  fi
  
  # Nohang status
  if systemctl is-active --quiet nohang-desktop.service; then
    echo "• Nohang: Installed and active"
  else
    echo "• Nohang: Not installed"
  fi
  
  echo
  echo "Installed Services:"
  
  # Docker status
  if command -v docker >/dev/null; then
    # Store Docker version in a variable first to avoid nested command substitution
    docker_version=$(docker --version | cut -d' ' -f3 | tr -d ',')
    echo "• Docker: Installed ($docker_version)"
    
    # Check if Dockge is installed - use Docker ps to verify
    if docker ps 2>/dev/null | grep -q "dockge"; then
      echo "• Dockge container manager: Installed and running"
      echo "  - URL: http://$server_ip:5001"
      echo "  - First-time setup required on first access"
    else
      echo "• Dockge container manager: Not installed"
    fi
  else
    echo "• Docker: Not installed"
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
  
  if [ -n "$tools" ]; then
    echo "• Monitor and benchmark tools: $tools"
  else
    echo "• Monitor and benchmark tools: None installed"
  fi
  
  echo
}

# Function to clean up and complete setup
finalize_setup() {
  msg_info "Finalizing setup..."
  
  # System cleanup
  apt autoremove -y
  apt clean
  
  # Generate and display the summary
  display_summary
  
  msg_ok "Debian Express Setup completed successfully!"
  echo
  echo "Your server has been configured according to your preferences."
  echo
  echo "For best results, it's recommended to reboot your server now."
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

# Main function to orchestrate the setup process
main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  
  # Confirmation to proceed
  if ! get_yes_no "This script will help you set up and optimize your Debian-based server. Do you want to proceed?"; then
    echo "Setup cancelled. No changes were made."
    exit 0
  fi
  
  # Core configuration
  update_system
  configure_hostname
  configure_timezone
  configure_locale
  configure_root_password
  configure_user
  
  # System optimization
  optimize_system
  
  # Monitoring and management tools
  setup_monitoring_tools
  
  # Container setup
  setup_containers
  
  # Finalize setup
  finalize_setup
}

# Run the main function
main "$@"
