#!/usr/bin/env bash

# Debian Express Tools
# Management & Monitoring Tools Installation Script
# License: MIT
# Description: Installs monitoring and management tools for Debian-based servers

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

# Cache system information
SERVER_IP=""
OS_NAME=""
OS_VERSION=""
OS_PRETTY=""
APT_UPDATED=false

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

# Function to get yes/no input
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

# Check root privileges
check_root() {
  if [[ "$EUID" -ne 0 ]]; then
    msg_error "This script must be run as root"
    exit 1
  fi
}

# Check Debian-based system
check_debian_based() {
  if [ ! -f /etc/debian_version ]; then
    msg_error "This script is designed for Debian-based systems only!"
    exit 1
  fi
}

# Detect OS version
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

# Cache server IP
cache_server_ip() {
  if [ -z "$SERVER_IP" ]; then
    SERVER_IP=$(hostname -I | awk '{print $1}')
  fi
}

# Run apt update
run_apt_update() {
  if [ "$APT_UPDATED" = false ]; then
    apt update
    APT_UPDATED=true
  fi
}

# Display banner
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

  echo -e "\n${BL}Management & Monitoring Tools${CL}\n"
}

###########################
# MONITORING TOOLS
###########################

install_monitoring_tools() {
  if ! get_yes_no "Install monitoring tools? (Fastfetch, Btop, Speedtest)"; then
    msg_info "Skipping monitoring tools"
    return
  fi

  msg_info "Installing monitoring tools..."

  # Fastfetch
  if get_yes_no "Install Fastfetch? (System information display)"; then
    if [ "$OS_NAME" = "Ubuntu" ]; then
      add-apt-repository ppa:zhangsongcui3371/fastfetch -y
      run_apt_update
      apt install -y fastfetch
    else
      apt install -y fastfetch 2>/dev/null || {
        msg_error "Fastfetch not available. Install manually if needed."
      }
    fi
    msg_ok "Fastfetch installed"
  fi

  # Btop
  if get_yes_no "Install Btop? (Modern resource monitor)"; then
    apt install -y btop
    msg_ok "Btop installed"
  fi

  # Speedtest-cli
  if get_yes_no "Install Speedtest-cli? (Internet speed test)"; then
    apt install -y speedtest-cli
    msg_ok "Speedtest-cli installed"
  fi
}

###########################
# DOCKER & CONTAINERS
###########################

install_docker() {
  if ! get_yes_no "Install Docker?"; then
    msg_info "Skipping Docker installation"
    return
  fi

  if command -v docker >/dev/null; then
    msg_info "Docker already installed"
    return
  fi

  msg_info "Installing Docker..."

  if ! curl -fsSL https://get.docker.com | sh; then
    msg_error "Docker installation failed"
    return 1
  fi

  # Add users to docker group
  existing_users=$(awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' /etc/passwd | sort)

  if [ -n "$existing_users" ]; then
    if get_yes_no "Add users to docker group? (Allows running Docker without sudo)"; then
      echo "Available users: $existing_users"
      echo
      for user in $existing_users; do
        if get_yes_no "Add $user to docker group?"; then
          usermod -aG docker "$user"
          msg_ok "$user added to docker group"
        fi
      done
    fi
  fi

  systemctl enable --now docker
  apt install -y docker-compose-plugin

  msg_ok "Docker installed"
}

install_dockge() {
  if ! command -v docker >/dev/null; then
    msg_info "Docker not installed. Skipping Dockge."
    return
  fi

  if ! get_yes_no "Install Dockge? (Web UI for Docker Compose)"; then
    msg_info "Skipping Dockge"
    return
  fi

  msg_info "Installing Dockge..."

  mkdir -p /opt/stacks/dockge/data
  cd /opt/stacks/dockge

  curl -fsSL https://raw.githubusercontent.com/louislam/dockge/master/compose.yaml -o docker-compose.yml

  if docker compose up -d; then
    cache_server_ip
    msg_ok "Dockge installed successfully"
    echo
    echo "Access Dockge at: http://$SERVER_IP:5001"
    echo "Create admin account on first login"
    echo
  else
    msg_error "Dockge installation failed"
  fi
}

###########################
# VPN SETUP
###########################

setup_vpn() {
  if ! get_yes_no "Set up a VPN? (Tailscale or Netbird)"; then
    msg_info "Skipping VPN setup"
    return
  fi

  echo "Select VPN provider:"
  echo
  echo -e "${HIGHLIGHT}1${CL}) Tailscale"
  echo -e "${HIGHLIGHT}2${CL}) Netbird"
  echo
  echo -n "Enter option [1-2]: "
  read -r vpn_choice
  echo

  case $vpn_choice in
    1) setup_tailscale ;;
    2) setup_netbird ;;
    *) msg_info "Invalid option. Skipping VPN." ;;
  esac
}

setup_tailscale() {
  msg_info "Installing Tailscale..."

  if ! curl -fsSL https://tailscale.com/install.sh | sh; then
    msg_error "Tailscale installation failed"
    return 1
  fi

  if get_yes_no "Do you have a Tailscale auth key?"; then
    echo -n "Enter auth key: "
    read -r auth_key
    echo
    tailscale up --authkey="$auth_key"
  else
    tailscale up
    msg_info "Please authenticate using the URL above"
  fi

  tailscale_ip=$(tailscale ip 2>/dev/null || echo "Unknown")
  msg_ok "Tailscale configured"
}

setup_netbird() {
  msg_info "Installing Netbird..."

  if ! curl -fsSL https://pkgs.netbird.io/install.sh | sh; then
    msg_error "Netbird installation failed"
    return 1
  fi

  echo -n "Enter Netbird setup key: "
  read -r setup_key
  echo

  if [ -n "$setup_key" ]; then
    netbird up --setup-key "$setup_key"
    msg_ok "Netbird configured"
  else
    msg_error "No setup key provided"
  fi
}

###########################
# SUMMARY
###########################

display_summary() {
  cache_server_ip

  echo
  echo "=== Installed Tools Summary ==="
  echo
  echo "System: $(hostname) - $SERVER_IP"
  echo

  command -v fastfetch >/dev/null && echo "• Fastfetch: Installed"
  command -v btop >/dev/null && echo "• Btop: Installed"
  command -v speedtest-cli >/dev/null && echo "• Speedtest-cli: Installed"
  command -v docker >/dev/null && echo "• Docker: Installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
  docker ps 2>/dev/null | grep -q dockge && echo "• Dockge: Installed (http://$SERVER_IP:5001)"

  # Check VPN status
  if command -v tailscale >/dev/null; then
    tailscale_ip=$(tailscale ip 2>/dev/null || echo "Not connected")
    echo "• Tailscale: Installed (IP: $tailscale_ip)"
  fi
  if command -v netbird >/dev/null; then
    echo "• Netbird: Installed"
  fi

  echo
}

finalize() {
  msg_info "Finalizing installation..."

  apt autoremove -y > /dev/null 2>&1
  apt clean

  display_summary

  msg_ok "Tool installation completed!"
  echo
  echo "Your management and monitoring tools are ready to use."
  echo
}

###########################
# MAIN
###########################

main() {
  check_root
  check_debian_based
  display_banner
  detect_os
  cache_server_ip

  if ! get_yes_no "Install management and monitoring tools?"; then
    echo "Installation cancelled."
    exit 0
  fi

  install_monitoring_tools
  install_docker
  install_dockge
  setup_vpn

  finalize
}

main "$@"
