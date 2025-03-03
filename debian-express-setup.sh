#!/usr/bin/env bash

# Debian Express Setup
# Part 1: System Setup & Optimization Script
# Author: [Your Name]
# License: MIT
# Description: Sets up and optimizes Debian-based servers with essential tools

# Define colors and formatting with better contrast
RD=$(echo -e "\033[01;31m")
GN=$(echo -e "\033[0;32m")  # Changed to darker green for better contrast
YW=$(echo -e "\033[33m")
BL=$(echo -e "\033[0;34m")
CL=$(echo -e "\033[m")
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${YW}ℹ️${CL}"

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
}

# Function to display info messages
msg_info() {
  echo -e "${INFO} $1"
}

# Function to display error messages
msg_error() {
  echo -e "${CROSS} $1"
}

# Record installed service for the security script to find
record_installed_service() {
  local service="$1"
  local port="$2"
  echo "$service:$port" >> "$STATE_FILE"
  msg_info "Recorded $service (port $port) for firewall configuration"
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
  ____       _                ____            _                 
 / ___|  ___| |_ _   _ _ __  / ___|  ___  ___| |_ _   _ _ __   
 \___ \ / _ \ __| | | | '_ \ \___ \ / _ \/ __| __| | | | '_ \  
  ___) |  __/ |_| |_| | |_) | ___) |  __/ (__| |_| |_| | |_) | 
 |____/ \___|\__|\__,_| .__/ |____/ \___|\___|\__|\__,_| .__/  
                      |_|                              |_|     
EOF

  echo -e "\n${BL}Welcome to Debian Express Setup!${CL}\n"
  echo -e "Part 1: System Setup & Optimization\n"
  echo -e "This script will help you configure, optimize, and install tools on your Debian-based server."
  echo -e "Run debian-express-secure.sh after this script to enable security features.\n"
}

# Preconfigure postfix to use local-only delivery and avoid interactive prompts
configure_postfix_noninteractive() {
  if ! dpkg -s postfix >/dev/null 2>&1; then
    # Preconfigure postfix to avoid prompts
    debconf-set-selections <<EOF
postfix postfix/mailname string $(hostname -f)
postfix postfix/main_mailer_type string 'Local only'
EOF
    msg_info "Pre-configured postfix for non-interactive installation"
  fi
}

#########################
# 1. CORE CONFIGURATION #
#########################

# Function to update and upgrade the system
update_system() {
  if whiptail --title "System Update" --yesno "Do you want to update and upgrade system packages?" 8 60; then
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
  new_hostname=$(whiptail --inputbox "Current hostname: $current_hostname\n\nEnter new hostname (leave empty to keep current):" 10 60 "$current_hostname" 3>&1 1>&2 2>&3)
  
  if [ $? -eq 0 ] && [ "$new_hostname" != "$current_hostname" ] && [ ! -z "$new_hostname" ]; then
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
  if whiptail --title "Timezone Configuration" --yesno "Current timezone: $current_timezone\n\nDo you want to change the timezone?" 10 60; then
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

  if whiptail --title "Locale Configuration" --yesno "Current locale: $readable_locale\n\nDo you want to configure system locale?" 10 60; then
    dpkg-reconfigure locales
    new_locale=$(locale | grep LANG= | cut -d= -f2)
    msg_ok "Locale set to $new_locale"
  else
    msg_info "Locale unchanged"
  fi
}

# Function to manage root password
configure_root_password() {
  if whiptail --title "Root Password" --yesno "Do you want to set/change the root password?" 8 60; then
    passwd root
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
          return
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
}

########################
# 2. SYSTEM OPTIMIZATION
########################

# Function to optimize system parameters
optimize_system() {
  if whiptail --title "System Optimization" --yesno "Would you like to apply system optimizations?" 8 70; then
    # Call each optimization function
    configure_swap
    optimize_io_scheduler
    optimize_kernel_parameters
    install_nohang
    disable_unused_services
    
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

# Function to optimize IO scheduler
optimize_io_scheduler() {
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
  else
    msg_info "I/O scheduler optimization skipped"
  fi
}

# Function to optimize kernel parameters
optimize_kernel_parameters() {
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
  else
    msg_info "Kernel parameter optimization skipped"
  fi
}

# Function to install nohang to prevent system freezes
install_nohang() {
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
}

# Function to disable unused services
disable_unused_services() {
  if whiptail --title "Disable Unused Services" --yesno "Would you like to disable commonly unused services to save resources?" 8 70; then
    # Track services we've configured
    configured_services=""
    if [ -f "$STATE_FILE" ]; then
      configured_services=$(cat "$STATE_FILE" | cut -d: -f1 | tr '\n' '|')
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

###################################
# 3. MANAGEMENT & MONITORING TOOLS
###################################

# Function to set up monitoring and management tools
setup_monitoring_tools() {
  msg_info "Setting up monitoring and management tools..."
  
  # Call each tool installation function
  setup_management_panel
  install_monitor_benchmark_tools
  setup_logwatch
  install_restic
  
  msg_ok "Monitoring and management tools setup completed"
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
  
  # Configure postfix noninteractively
  configure_postfix_noninteractive
  
  # Add Webmin repository and install
  curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
  sh setup-repos.sh
  apt install -y webmin
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    webmin_port=10000
    
    msg_ok "Webmin installed successfully"
    
    # Record for firewall configuration
    record_installed_service "webmin" "$webmin_port"
    
    # Save info for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/webmin.txt" << EOF
Webmin has been installed successfully.

You can access the Webmin interface at:
https://$server_ip:$webmin_port

Default login: Current system username/password
EOF

    whiptail --title "Webmin Installed" --msgbox "Webmin has been installed successfully.\n\nYou can access the Webmin interface at:\nhttps://$server_ip:$webmin_port\n\nDefault login: Current system username/password" 12 70
  else
    msg_error "Webmin installation failed"
  fi
}

# Function for minimal Docker installation (to avoid duplicate prompts)
setup_docker_minimal() {
  # Only install if not already installed
  if ! command -v docker >/dev/null; then
    msg_info "Installing Docker (required dependency)..."
    
    # Install Docker using the official script
    curl -fsSL https://get.docker.com | sh
    
    # Enable and start Docker service
    systemctl enable --now docker
    
    # Install Docker Compose plugin
    apt install -y docker-compose-plugin
    
    msg_ok "Docker installed successfully (as a dependency)"
    
    # Record docker service
    record_installed_service "docker" "2375"
    
    # Mark Docker as installed
    DOCKER_INSTALLED=true
  else
    msg_info "Docker already installed, continuing with setup"
  fi
}

# Function to set up Easy Panel
setup_easy_panel() {
  msg_info "Installing Easy Panel..."
  
  # Check if Docker is installed and install if needed
  setup_docker_minimal
  
  # Install Easy Panel
  curl -fsSL https://get.easypanel.io | sh
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    easypanel_port=3000
    
    msg_ok "Easy Panel installed successfully"
    
    # Record for firewall configuration
    record_installed_service "easypanel" "$easypanel_port"
    
    # Save info for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/easypanel.txt" << EOF
Easy Panel has been installed successfully.

You can access the Easy Panel interface at:
http://$server_ip:$easypanel_port

Follow the on-screen instructions to complete setup.
EOF

    whiptail --title "Easy Panel Installed" --msgbox "Easy Panel has been installed successfully.\n\nYou can access the Easy Panel interface at:\nhttp://$server_ip:$easypanel_port\n\nFollow the on-screen instructions to complete setup." 12 70
  else
    msg_error "Easy Panel installation failed"
  fi
}

# Function to set up monitoring tools
install_monitor_benchmark_tools() {
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

# Function to set up Logwatch
setup_logwatch() {
  if whiptail --title "Logwatch Setup" --yesno "Would you like to install and configure Logwatch for log monitoring?\n\nLogwatch provides daily system log analysis and reports." 10 70; then
    msg_info "Installing Logwatch..."
    
    # Configure postfix noninteractively
    configure_postfix_noninteractive
    
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
      mkdir -p "$TEMP_DIR/info"
      cat > "$TEMP_DIR/info/logwatch.txt" << EOF
Logwatch has been installed and configured.

Daily reports will be sent to: $admin_email
Report frequency: Daily (previous day's logs)
Report format: HTML
Detail level: Medium
EOF
    else
      # Default configuration if no email provided
      msg_info "Logwatch installed but not configured"
    fi
  else
    msg_info "Logwatch setup skipped"
  fi
}

# Simplified function to install Restic backup tool
install_restic() {
  if whiptail --title "Backup Tool" --yesno "Would you like to install Restic backup tool?\n\nRestic is a modern, fast and secure backup program." 10 70; then
    msg_info "Installing Restic backup tool..."
    apt install -y restic
    
    if [[ $? -eq 0 ]]; then
      msg_ok "Restic backup tool installed successfully"
      
      # Save information for final summary
      mkdir -p "$TEMP_DIR/info"
      cat > "$TEMP_DIR/info/restic.txt" << EOF
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

###########################
# 4. CONTAINER MANAGEMENT #
###########################

# Function to set up Docker and container tools
setup_containers() {
  msg_info "Setting up container management..."
  
  # Docker installation (only if not already installed)
  if [ "$DOCKER_INSTALLED"
  #!/usr/bin/env bash

# Debian Express Setup
# Part 1: System Setup & Optimization Script
# Author: [Your Name]
# License: MIT
# Description: Sets up and optimizes Debian-based servers with essential tools

# Define colors and formatting with better contrast
RD=$(echo -e "\033[01;31m")
GN=$(echo -e "\033[0;32m")  # Changed to darker green for better contrast
YW=$(echo -e "\033[33m")
BL=$(echo -e "\033[0;34m")
CL=$(echo -e "\033[m")
CM="${GN}✓${CL}"
CROSS="${RD}✗${CL}"
INFO="${YW}ℹ️${CL}"

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
}

# Function to display info messages
msg_info() {
  echo -e "${INFO} $1"
}

# Function to display error messages
msg_error() {
  echo -e "${CROSS} $1"
}

# Record installed service for the security script to find
record_installed_service() {
  local service="$1"
  local port="$2"
  echo "$service:$port" >> "$STATE_FILE"
  msg_info "Recorded $service (port $port) for firewall configuration"
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
  ____       _                ____            _                 
 / ___|  ___| |_ _   _ _ __  / ___|  ___  ___| |_ _   _ _ __   
 \___ \ / _ \ __| | | | '_ \ \___ \ / _ \/ __| __| | | | '_ \  
  ___) |  __/ |_| |_| | |_) | ___) |  __/ (__| |_| |_| | |_) | 
 |____/ \___|\__|\__,_| .__/ |____/ \___|\___|\__|\__,_| .__/  
                      |_|                              |_|     
EOF

  echo -e "\n${BL}Welcome to Debian Express Setup!${CL}\n"
  echo -e "Part 1: System Setup & Optimization\n"
  echo -e "This script will help you configure, optimize, and install tools on your Debian-based server."
  echo -e "Run debian-express-secure.sh after this script to enable security features.\n"
}

# Preconfigure postfix to use local-only delivery and avoid interactive prompts
configure_postfix_noninteractive() {
  if ! dpkg -s postfix >/dev/null 2>&1; then
    # Preconfigure postfix to avoid prompts
    debconf-set-selections <<EOF
postfix postfix/mailname string $(hostname -f)
postfix postfix/main_mailer_type string 'Local only'
EOF
    msg_info "Pre-configured postfix for non-interactive installation"
  fi
}

#########################
# 1. CORE CONFIGURATION #
#########################

# Function to update and upgrade the system
update_system() {
  if whiptail --title "System Update" --yesno "Do you want to update and upgrade system packages?" 8 60; then
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
  new_hostname=$(whiptail --inputbox "Current hostname: $current_hostname\n\nEnter new hostname (leave empty to keep current):" 10 60 "$current_hostname" 3>&1 1>&2 2>&3)
  
  if [ $? -eq 0 ] && [ "$new_hostname" != "$current_hostname" ] && [ ! -z "$new_hostname" ]; then
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
  if whiptail --title "Timezone Configuration" --yesno "Current timezone: $current_timezone\n\nDo you want to change the timezone?" 10 60; then
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

  if whiptail --title "Locale Configuration" --yesno "Current locale: $readable_locale\n\nDo you want to configure system locale?" 10 60; then
    dpkg-reconfigure locales
    new_locale=$(locale | grep LANG= | cut -d= -f2)
    msg_ok "Locale set to $new_locale"
  else
    msg_info "Locale unchanged"
  fi
}

# Function to manage root password
configure_root_password() {
  if whiptail --title "Root Password" --yesno "Do you want to set/change the root password?" 8 60; then
    passwd root
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
          return
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
}

########################
# 2. SYSTEM OPTIMIZATION
########################

# Function to optimize system parameters
optimize_system() {
  if whiptail --title "System Optimization" --yesno "Would you like to apply system optimizations?" 8 70; then
    # Call each optimization function
    configure_swap
    optimize_io_scheduler
    optimize_kernel_parameters
    install_nohang
    disable_unused_services
    
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

# Function to optimize IO scheduler
optimize_io_scheduler() {
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
  else
    msg_info "I/O scheduler optimization skipped"
  fi
}

# Function to optimize kernel parameters
optimize_kernel_parameters() {
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
  else
    msg_info "Kernel parameter optimization skipped"
  fi
}

# Function to install nohang to prevent system freezes
install_nohang() {
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
}

# Function to disable unused services
disable_unused_services() {
  if whiptail --title "Disable Unused Services" --yesno "Would you like to disable commonly unused services to save resources?" 8 70; then
    # Track services we've configured
    configured_services=""
    if [ -f "$STATE_FILE" ]; then
      configured_services=$(cat "$STATE_FILE" | cut -d: -f1 | tr '\n' '|')
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

###################################
# 3. MANAGEMENT & MONITORING TOOLS
###################################

# Function to set up monitoring and management tools
setup_monitoring_tools() {
  msg_info "Setting up monitoring and management tools..."
  
  # Call each tool installation function
  setup_management_panel
  install_monitor_benchmark_tools
  setup_logwatch
  install_restic
  
  msg_ok "Monitoring and management tools setup completed"
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
  
  # Configure postfix noninteractively
  configure_postfix_noninteractive
  
  # Add Webmin repository and install
  curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
  sh setup-repos.sh
  apt install -y webmin
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    webmin_port=10000
    
    msg_ok "Webmin installed successfully"
    
    # Record for firewall configuration
    record_installed_service "webmin" "$webmin_port"
    
    # Save info for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/webmin.txt" << EOF
Webmin has been installed successfully.

You can access the Webmin interface at:
https://$server_ip:$webmin_port

Default login: Current system username/password
EOF

    whiptail --title "Webmin Installed" --msgbox "Webmin has been installed successfully.\n\nYou can access the Webmin interface at:\nhttps://$server_ip:$webmin_port\n\nDefault login: Current system username/password" 12 70
  else
    msg_error "Webmin installation failed"
  fi
}

# Function for minimal Docker installation (to avoid duplicate prompts)
setup_docker_minimal() {
  # Only install if not already installed
  if ! command -v docker >/dev/null; then
    msg_info "Installing Docker (required dependency)..."
    
    # Install Docker using the official script
    curl -fsSL https://get.docker.com | sh
    
    # Enable and start Docker service
    systemctl enable --now docker
    
    # Install Docker Compose plugin
    apt install -y docker-compose-plugin
    
    msg_ok "Docker installed successfully (as a dependency)"
    
    # Record docker service
    record_installed_service "docker" "2375"
    
    # Mark Docker as installed
    DOCKER_INSTALLED=true
  else
    msg_info "Docker already installed, continuing with setup"
  fi
}

# Function to set up Easy Panel
setup_easy_panel() {
  msg_info "Installing Easy Panel..."
  
  # Check if Docker is installed and install if needed
  setup_docker_minimal
  
  # Install Easy Panel
  curl -fsSL https://get.easypanel.io | sh
  
  if [[ $? -eq 0 ]]; then
    # Get server IP
    server_ip=$(hostname -I | awk '{print $1}')
    easypanel_port=3000
    
    msg_ok "Easy Panel installed successfully"
    
    # Record for firewall configuration
    record_installed_service "easypanel" "$easypanel_port"
    
    # Save info for summary
    mkdir -p "$TEMP_DIR/info"
    cat > "$TEMP_DIR/info/easypanel.txt" << EOF
Easy Panel has been installed successfully.

You can access the Easy Panel interface at:
http://$server_ip:$easypanel_port

Follow the on-screen instructions to complete setup.
EOF

    whiptail --title "Easy Panel Installed" --msgbox "Easy Panel has been installed successfully.\n\nYou can access the Easy Panel interface at:\nhttp://$server_ip:$easypanel_port\n\nFollow the on-screen instructions to complete setup." 12 70
  else
    msg_error "Easy Panel installation failed"
  fi
}

# Function to set up monitoring tools
install_monitor_benchmark_tools() {
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

# Function to set up Logwatch
setup_logwatch() {
  if whiptail --title "Logwatch Setup" --yesno "Would you like to install and configure Logwatch for log monitoring?\n\nLogwatch provides daily system log analysis and reports." 10 70; then
    msg_info "Installing Logwatch..."
    
    # Configure postfix noninteractively
    configure_postfix_noninteractive
    
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
      mkdir -p "$TEMP_DIR/info"
      cat > "$TEMP_DIR/info/logwatch.txt" << EOF
Logwatch has been installed and configured.

Daily reports will be sent to: $admin_email
Report frequency: Daily (previous day's logs)
Report format: HTML
Detail level: Medium
EOF
    else
      # Default configuration if no email provided
      msg_info "Logwatch installed but not configured"
    fi
  else
    msg_info "Logwatch setup skipped"
  fi
}

# Simplified function to install Restic backup tool
install_restic() {
  if whiptail --title "Backup Tool" --yesno "Would you like to install Restic backup tool?\n\nRestic is a modern, fast and secure backup program." 10 70; then
    msg_info "Installing Restic backup tool..."
    apt install -y restic
    
    if [[ $? -eq 0 ]]; then
      msg_ok "Restic backup tool installed successfully"
      
      # Save information for final summary
      mkdir -p "$TEMP_DIR/info"
      cat > "$TEMP_DIR/info/restic.txt" << EOF
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

###########################
# 4. CONTAINER MANAGEMENT #
###########################

# Function to set up Docker and container tools
setup_containers() {
  msg_info "Setting up container management..."
  
  # Docker installation (only if not already installed)
  if [ "$DOCKER_INSTALLED" = false ]; then
