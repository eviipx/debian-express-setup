#!/usr/bin/env bash

# Debian Express Core
# Core Configuration & Performance Optimization Script
# License: MIT
# Description: Sets up and optimizes Debian-based servers

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

# Flag to track if apt update has been run
APT_UPDATED=false

# Cache system information (populated in main function)
SERVER_IP=""
OS_NAME=""
OS_VERSION=""
OS_PRETTY=""
SERVER_TYPE=""  # "vps" or "local"

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
    return 1
  fi
}

# Cache server IP address
cache_server_ip() {
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
  fi
}

# Detect server type (VPS or local)
detect_server_type() {
  echo "What type of server is this?"
  echo
  echo -e "${HIGHLIGHT}1${CL}) VPS / Cloud Server (AWS, DigitalOcean, Linode, Hetzner, etc.)"
  echo -e "${HIGHLIGHT}2${CL}) Local / Home Server (bare metal, Proxmox VM, etc.)"
  echo
  echo -n "Enter option [1-2]: "
  read -r server_choice
  echo

  case $server_choice in
    1)
      SERVER_TYPE="vps"
      msg_ok "Configured for VPS/Cloud (conservative optimizations)"
      ;;
    2)
      SERVER_TYPE="local"
      msg_ok "Configured for Local/Home Server (full optimizations)"
      ;;
    *)
      SERVER_TYPE="vps"
      msg_info "Invalid option. Defaulting to VPS (safer choice)"
      ;;
  esac
}

# Run apt update only if not already done
run_apt_update() {
  if [ "$APT_UPDATED" = false ]; then
    apt update
    APT_UPDATED=true
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

  echo -e "\n${BL}Core Configuration & Performance Optimization${CL}\n"
}

#########################
# 1. CORE CONFIGURATION #
#########################

# Function to update and upgrade the system
update_system() {
  if get_yes_no "Do you want to update and upgrade system packages?"; then
    msg_info "Updating and upgrading system packages..."
    apt update && apt upgrade -y
    APT_UPDATED=true
    msg_ok "System packages updated and upgraded"
  else
    msg_info "Skipping system update"
  fi
}

# Function to set hostname
configure_hostname() {
  if get_yes_no "Do you want to change the system hostname?"; then
    current_hostname=$(hostname)
    echo -e "Current hostname: ${HIGHLIGHT}$current_hostname${CL}"
    echo -n "Enter new hostname: "
    read -r new_hostname
    echo

    if [ -n "$new_hostname" ] && [ "$new_hostname" != "$current_hostname" ]; then
      hostnamectl set-hostname "$new_hostname"
      sed -i "s/127.0.1.1.*$current_hostname/127.0.1.1\t$new_hostname/g" /etc/hosts
      msg_ok "Hostname changed to $new_hostname"
    else
      msg_info "Hostname unchanged"
    fi
  else
    msg_info "Skipping hostname configuration"
  fi
}

# Function to set timezone
configure_timezone() {
  if get_yes_no "Do you want to change the timezone?"; then
    current_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    echo -e "Current timezone: ${HIGHLIGHT}$current_timezone${CL}"
    dpkg-reconfigure tzdata
    new_timezone=$(timedatectl | grep "Time zone" | awk '{print $3}')
    msg_ok "Timezone set to $new_timezone"
  else
    msg_info "Skipping timezone configuration"
  fi
}

# Function to configure locale
configure_locale() {
  if get_yes_no "Do you want to configure system locale?"; then
    current_locale=$(locale | grep LANG= | cut -d= -f2)
    echo -e "Current locale: ${HIGHLIGHT}$current_locale${CL}"
    dpkg-reconfigure locales
    new_locale=$(locale | grep LANG= | cut -d= -f2)
    msg_ok "Locale set to $new_locale"
  else
    msg_info "Skipping locale configuration"
  fi
}

# Function to manage root password
configure_root_password() {
  if get_yes_no "Do you want to set/change the root password?"; then
    passwd root
    echo
    msg_ok "Root password updated"
  else
    msg_info "Skipping root password configuration"
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
      if id "$username" &>/dev/null; then
        msg_error "User $username already exists"
      else
        adduser "$username"
        echo
        apt install -y sudo
        usermod -aG sudo "$username"
        msg_ok "User $username created and added to sudo group"
      fi
    else
      msg_info "User creation skipped"
    fi
  else
    msg_info "Skipping user creation"
  fi
}

########################
# 2. SYSTEM OPTIMIZATION
########################

# Function to optimize system parameters
optimize_system() {
  if get_yes_no "Would you like to apply performance optimizations to your system?"; then
    configure_swap
    optimize_io_scheduler
    optimize_kernel_parameters
    enable_tcp_bbr
    increase_file_limits
    configure_journal_limits
    disable_unused_services
    install_nohang
    disable_ipv6
    configure_tmpfs

    msg_ok "System optimization completed"
  else
    msg_info "Skipping all system optimizations"
  fi
}

# Function to configure swap based on RAM
configure_swap() {
  if ! get_yes_no "Configure swap space? (Recommended for servers with <16GB RAM)"; then
    msg_info "Skipping swap configuration"
    return
  fi

  # Check if swap exists and list all swap files
  swap_exists=0
  swap_size=0
  if [ "$(swapon --show | wc -l)" -gt 0 ]; then
    swap_exists=1
    swap_size=$(free -m | grep Swap | awk '{print $2}')
  fi

  # Get system RAM
  ram_size=$(free -m | grep Mem | awk '{print $2}')

  # Determine recommended swap size based on RAM and server type
  if [ "$SERVER_TYPE" = "vps" ]; then
    # VPS: Conservative swap (disk I/O is slower, space is limited)
    if [ $ram_size -lt 2048 ]; then
      recommended_swap=$((ram_size * 2))  # <2GB: 2x RAM
    elif [ $ram_size -lt 4096 ]; then
      recommended_swap=$ram_size           # 2-4GB: 1x RAM
    else
      recommended_swap=4096                # 4GB+: Cap at 4GB
    fi
  else
    # Local server: More generous swap (faster local storage)
    if [ $ram_size -lt 2048 ]; then
      recommended_swap=$((ram_size * 2))  # <2GB: 2x RAM
    elif [ $ram_size -lt 4096 ]; then
      recommended_swap=$ram_size           # 2-4GB: 1x RAM
    elif [ $ram_size -lt 8192 ]; then
      recommended_swap=4096                # 4-8GB: 4GB
    elif [ $ram_size -lt 16384 ]; then
      recommended_swap=8192                # 8-16GB: 8GB
    else
      recommended_swap=8192                # 16GB+: Cap at 8GB
    fi
  fi

  # Display swap information
  if [ $swap_exists -eq 1 ]; then
    echo -e "Current swap: ${HIGHLIGHT}${swap_size}MB${CL}, RAM: ${HIGHLIGHT}${ram_size}MB${CL}"
    echo -e "Recommended swap: ${HIGHLIGHT}${recommended_swap}MB${CL}"
    echo

    # Show existing swap files
    if [ "$(swapon --show --noheadings | wc -l)" -gt 1 ]; then
      echo -e "${YW}Warning: Multiple swap files detected:${CL}"
      swapon --show
      echo
    fi

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
        remove_all_swap
        create_swap_file "${recommended_swap}"
        ;;
      3)
        echo -n "Enter desired swap size in MB: "
        read -r custom_size
        echo
        if [ -n "$custom_size" ]; then
          remove_all_swap
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

# Function to remove all existing swap files
remove_all_swap() {
  msg_info "Removing all existing swap..."

  # Get list of all active swap files
  local swap_files=$(swapon --show=NAME --noheadings)

  if [ -n "$swap_files" ]; then
    # Disable all swap
    swapoff -a

    # Remove each swap file and its fstab entry
    while IFS= read -r swap_file; do
      # Only remove if it's a file (not a partition)
      if [ -f "$swap_file" ]; then
        msg_info "Removing $swap_file..."
        rm -f "$swap_file"

        # Remove from fstab
        if grep -q "$swap_file" /etc/fstab 2>/dev/null; then
          sed -i "\|$swap_file|d" /etc/fstab
        fi
      fi
    done <<< "$swap_files"

    msg_ok "All existing swap removed"
  fi
}

# Function to create and configure swap file
create_swap_file() {
  local size_mb=$1

  msg_info "Creating ${size_mb}MB swap file at /swapfile..."

  # Check available disk space
  available_space=$(df -m / | tail -1 | awk '{print $4}')
  if [ "$available_space" -lt "$size_mb" ]; then
    msg_error "Not enough disk space. Available: ${available_space}MB, Required: ${size_mb}MB"
    return 1
  fi

  # Create new swap file (try fallocate first, fall back to dd if it fails)
  if ! fallocate -l ${size_mb}M /swapfile 2>/dev/null; then
    msg_info "fallocate not supported, using dd instead (this may take a moment)..."
    if ! dd if=/dev/zero of=/swapfile bs=1M count=${size_mb} status=progress; then
      msg_error "Failed to create swap file"
      return 1
    fi
  fi

  chmod 600 /swapfile
  if ! mkswap /swapfile; then
    msg_error "Failed to format swap file"
    rm -f /swapfile
    return 1
  fi

  if ! swapon /swapfile; then
    msg_error "Failed to enable swap file"
    rm -f /swapfile
    return 1
  fi

  # Clean up any old swap entries from fstab and add new one
  sed -i '/[[:space:]]swap[[:space:]]/d' /etc/fstab
  echo '/swapfile none swap sw 0 0' >> /etc/fstab

  # Configure swappiness and cache pressure
  echo 'vm.swappiness=10' > /etc/sysctl.d/99-swappiness.conf
  echo 'vm.vfs_cache_pressure=50' >> /etc/sysctl.d/99-swappiness.conf
  sysctl -p /etc/sysctl.d/99-swappiness.conf > /dev/null

  msg_ok "Swap file created and configured (${size_mb}MB at /swapfile)"
}

# Function to optimize IO scheduler
optimize_io_scheduler() {
  # Skip for VPS - hypervisor handles I/O scheduling
  if [ "$SERVER_TYPE" = "vps" ]; then
    msg_info "Skipping I/O scheduler (VPS: hypervisor manages disk I/O)"
    return
  fi

  if ! get_yes_no "Optimize I/O scheduler? Improves disk performance for SSDs/HDDs"; then
    msg_info "Skipping I/O scheduler optimization"
    return
  fi

  # Check for SSD
  has_ssd=false
  for drive in $(lsblk -d -o name | tail -n +2); do
    if [ -f "/sys/block/$drive/queue/rotational" ]; then
      if [ "$(cat /sys/block/$drive/queue/rotational)" -eq 0 ]; then
        has_ssd=true
      fi
    fi
  done

  if $has_ssd; then
    cat > /etc/udev/rules.d/60-scheduler.rules << EOF
# Set scheduler for SSD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="0", ATTR{queue/scheduler}="mq-deadline"
# Set scheduler for HDD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/rotational}=="1", ATTR{queue/scheduler}="bfq"
EOF
    msg_ok "I/O scheduler optimized for SSDs and HDDs"
  else
    cat > /etc/udev/rules.d/60-scheduler.rules << EOF
# Set scheduler for HDD
ACTION=="add|change", KERNEL=="sd[a-z]", ATTR{queue/scheduler}="bfq"
EOF
    msg_ok "I/O scheduler optimized for HDDs"
  fi
}

# Function to optimize kernel parameters
optimize_kernel_parameters() {
  if ! get_yes_no "Optimize kernel parameters? Improves system and network performance"; then
    msg_info "Skipping kernel parameter optimization"
    return
  fi

  # Different dirty ratios for VPS vs local
  if [ "$SERVER_TYPE" = "vps" ]; then
    # VPS: Lower dirty ratios (flush sooner, disk I/O is slower)
    dirty_ratio=5
    dirty_bg_ratio=3
  else
    # Local: Higher dirty ratios (local storage is faster)
    dirty_ratio=10
    dirty_bg_ratio=5
  fi

  cat > /etc/sysctl.d/99-performance.conf << EOF
# File system performance
vm.dirty_ratio = ${dirty_ratio}
vm.dirty_background_ratio = ${dirty_bg_ratio}

# Network performance
net.core.somaxconn = 1024
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_tw_reuse = 1

# System responsiveness
vm.swappiness = 10
vm.vfs_cache_pressure = 50
EOF

  sysctl -p /etc/sysctl.d/99-performance.conf > /dev/null
  msg_ok "Kernel parameters optimized"
}

# Function to enable TCP BBR
enable_tcp_bbr() {
  if ! get_yes_no "Enable TCP BBR congestion control? Significantly improves network throughput"; then
    msg_info "Skipping TCP BBR"
    return
  fi

  # Check if BBR is available
  if ! modprobe tcp_bbr 2>/dev/null; then
    msg_error "TCP BBR not available on this kernel"
    return 1
  fi

  cat >> /etc/sysctl.d/99-performance.conf << EOF

# TCP BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF

  sysctl -p /etc/sysctl.d/99-performance.conf > /dev/null
  msg_ok "TCP BBR enabled"
}

# Function to increase file descriptor limits
increase_file_limits() {
  if ! get_yes_no "Increase file descriptor limits? Essential for web servers and databases"; then
    msg_info "Skipping file descriptor limits"
    return
  fi

  # Update limits.conf
  cat >> /etc/security/limits.conf << EOF

# Increased file descriptor limits
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF

  # Update sysctl
  cat >> /etc/sysctl.d/99-performance.conf << EOF

# File descriptor limits
fs.file-max = 2097152
EOF

  sysctl -p /etc/sysctl.d/99-performance.conf > /dev/null
  msg_ok "File descriptor limits increased to 65535"
}

# Function to configure systemd journal limits
configure_journal_limits() {
  if ! get_yes_no "Limit systemd journal size? Prevents logs from consuming too much disk space"; then
    msg_info "Skipping journal limits"
    return
  fi

  # Different limits for VPS vs local
  if [ "$SERVER_TYPE" = "vps" ]; then
    # VPS: Smaller journal (disk space is limited)
    journal_max="200M"
    journal_file_max="50M"
  else
    # Local: Larger journal (more disk space available)
    journal_max="500M"
    journal_file_max="100M"
  fi

  mkdir -p /etc/systemd/journald.conf.d
  cat > /etc/systemd/journald.conf.d/00-journal-size.conf << EOF
[Journal]
SystemMaxUse=${journal_max}
SystemMaxFileSize=${journal_file_max}
MaxRetentionSec=2week
EOF

  systemctl restart systemd-journald
  msg_ok "Journal size limited to ${journal_max}"
}

# Function to disable unused services
disable_unused_services() {
  if ! get_yes_no "Disable unused services? (Bluetooth, printing, etc.) Saves RAM and improves security"; then
    msg_info "Skipping service cleanup"
    return
  fi

  local disabled_count=0

  for service in bluetooth.service cups.service ModemManager.service avahi-daemon.service; do
    if systemctl is-enabled --quiet "$service" 2>/dev/null; then
      systemctl disable --now "$service" 2>/dev/null || true
      ((disabled_count++))
    fi
  done

  if [ $disabled_count -gt 0 ]; then
    msg_ok "Disabled $disabled_count unnecessary services"
  else
    msg_info "No unnecessary services found to disable"
  fi
}

# Function to install nohang
install_nohang() {
  # Check RAM size
  ram_gb=$(free -g | grep Mem | awk '{print $2}')

  # Only offer nohang if RAM < 16GB
  if [ $ram_gb -ge 16 ]; then
    msg_info "Skipping nohang (you have ${ram_gb}GB RAM - not needed for systems with 16GB+)"
    return
  fi

  if ! get_yes_no "Install nohang? Prevents system freezes when memory is full (recommended for <16GB RAM)"; then
    msg_info "Skipping nohang installation"
    return
  fi

  msg_info "Installing nohang..."

  if [ "$OS_NAME" = "Ubuntu" ]; then
    add-apt-repository ppa:oibaf/test -y
    run_apt_update
    if apt install -y nohang; then
      systemctl enable --now nohang-desktop.service
      msg_ok "Nohang installed and configured"
    else
      msg_error "Failed to install nohang"
    fi
  else
    # For Debian, try standard repo
    if apt install -y nohang 2>/dev/null; then
      systemctl enable --now nohang-desktop.service
      msg_ok "Nohang installed and configured"
    else
      msg_error "Nohang not available in Debian repositories"
    fi
  fi
}

# Function to disable IPv6
disable_ipv6() {
  if ! get_yes_no "Disable IPv6? Only do this if you don't use IPv6 connectivity"; then
    msg_info "Keeping IPv6 enabled"
    return
  fi

  cat >> /etc/sysctl.d/99-performance.conf << EOF

# Disable IPv6
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

  sysctl -p /etc/sysctl.d/99-performance.conf > /dev/null
  msg_ok "IPv6 disabled"
}

# Function to configure tmpfs
configure_tmpfs() {
  if ! get_yes_no "Mount /tmp in RAM? Makes temporary files 100x faster"; then
    msg_info "Skipping tmpfs configuration"
    return
  fi

  # Detect RAM and set tmpfs size
  ram_gb=$(free -g | grep Mem | awk '{print $2}')

  if [ $ram_gb -lt 4 ]; then
    tmpfs_size="512M"
  elif [ $ram_gb -lt 8 ]; then
    tmpfs_size="1G"
  else
    tmpfs_size="2G"
  fi

  # Add to fstab if not already there
  if ! grep -q "tmpfs /tmp" /etc/fstab; then
    echo "tmpfs /tmp tmpfs defaults,noatime,mode=1777,size=$tmpfs_size 0 0" >> /etc/fstab
    mount -a
    msg_ok "/tmp mounted in RAM (${tmpfs_size} limit)"
  else
    msg_info "/tmp already configured as tmpfs"
  fi
}

#########################
# SUMMARY AND COMPLETION
#########################

# Function to display system information summary
display_summary() {
  cache_server_ip

  echo
  echo "=== Debian Express Core Configuration Summary ==="
  echo
  echo "System Information:"
  echo -e "• Hostname: ${HIGHLIGHT}$(hostname)${CL}"
  echo -e "• IP Address: ${HIGHLIGHT}$SERVER_IP${CL}"
  echo -e "• OS: ${HIGHLIGHT}$OS_PRETTY${CL}"
  if [ "$SERVER_TYPE" = "vps" ]; then
    echo -e "• Server Type: ${HIGHLIGHT}VPS/Cloud${CL}"
  else
    echo -e "• Server Type: ${HIGHLIGHT}Local/Home Server${CL}"
  fi
  echo

  # Swap status
  swap_size=$(free -h | grep Swap | awk '{print $2}')
  echo -e "• Swap: ${HIGHLIGHT}$swap_size${CL}"

  # Optimization status
  if [ -f /etc/sysctl.d/99-performance.conf ]; then
    echo -e "• System optimizations: ${HIGHLIGHT}Applied${CL}"

    # Check specific optimizations
    if grep -q "tcp_bbr" /etc/sysctl.d/99-performance.conf 2>/dev/null; then
      echo -e "  - TCP BBR: ${HIGHLIGHT}Enabled${CL}"
    fi

    if grep -q "disable_ipv6" /etc/sysctl.d/99-performance.conf 2>/dev/null; then
      echo -e "  - IPv6: ${HIGHLIGHT}Disabled${CL}"
    fi
  else
    echo -e "• System optimizations: ${HIGHLIGHT}Not applied${CL}"
  fi

  # I/O scheduler status
  if [ -f /etc/udev/rules.d/60-scheduler.rules ]; then
    echo -e "• I/O scheduler: ${HIGHLIGHT}Optimized${CL}"
  fi

  # Journal limits
  if [ -f /etc/systemd/journald.conf.d/00-journal-size.conf ]; then
    journal_configured=$(grep "SystemMaxUse" /etc/systemd/journald.conf.d/00-journal-size.conf | cut -d'=' -f2)
    echo -e "• Journal limits: ${HIGHLIGHT}Configured (${journal_configured})${CL}"
  fi

  # Nohang status
  if systemctl is-active --quiet nohang-desktop.service 2>/dev/null; then
    echo -e "• Nohang: ${HIGHLIGHT}Installed and active${CL}"
  fi

  # tmpfs status
  if grep -q "tmpfs /tmp" /etc/fstab; then
    tmpfs_size=$(grep "tmpfs /tmp" /etc/fstab | grep -oP 'size=\K[^ ]+')
    echo -e "• /tmp in RAM: ${HIGHLIGHT}Yes (${tmpfs_size})${CL}"
  fi

  echo
}

# Function to finalize setup
finalize_setup() {
  msg_info "Finalizing setup..."

  # System cleanup
  apt autoremove -y > /dev/null 2>&1
  apt clean

  # Display summary
  display_summary

  msg_ok "Debian Express Core configuration completed!"
  echo
  echo "Your server has been configured and optimized."
  echo
  echo "NEXT STEPS:"
  echo -e "1. Run ${HIGHLIGHT}deb-express-2-secure.sh${CL} to harden security"
  echo -e "2. Run ${HIGHLIGHT}deb-express-3-tools.sh${CL} to install management tools"
  echo
  echo "For best results, it's recommended to reboot your server now."
  echo

  if get_yes_no "Would you like to reboot now?"; then
    echo "Rebooting system in 5 seconds..."
    sleep 5
    reboot
  else
    echo "Please remember to reboot your system manually when convenient."
  fi
}

# Main function
main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  cache_server_ip
  detect_server_type

  if ! get_yes_no "This script will configure core settings and optimize your server. Proceed?"; then
    echo "Setup cancelled."
    exit 0
  fi

  # Core configuration
  update_system
  configure_hostname
  configure_timezone
  configure_locale
  configure_root_password
  configure_user

  # Performance optimization
  optimize_system

  # Finalize
  finalize_setup
}

# Run the main function
main "$@"
