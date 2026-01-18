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
  if ! get_yes_no "Install monitoring tools? (Fastfetch, Btop, Glances, LibreSpeed-cli)"; then
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

  # Glances
  if get_yes_no "Install Glances? (Advanced system monitor with web interface)"; then
    apt install -y glances
    msg_ok "Glances installed (run: glances)"
  fi

  # LibreSpeed-cli
  if get_yes_no "Install LibreSpeed-cli? (Lightweight speed test tool)"; then
    msg_info "Downloading LibreSpeed-cli..."
    ARCH=$(uname -m)
    case $ARCH in
      x86_64) ARCH="amd64" ;;
      aarch64) ARCH="arm64" ;;
      armv7l) ARCH="armv7" ;;
    esac

    curl -fsSL "https://github.com/librespeed/speedtest-cli/releases/latest/download/librespeed-cli_linux_${ARCH}" -o /usr/local/bin/librespeed-cli
    chmod +x /usr/local/bin/librespeed-cli
    msg_ok "LibreSpeed-cli installed (run: librespeed-cli)"
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

  # Create /srv/docker directory with proper permissions
  msg_info "Creating /srv/docker directory..."
  mkdir -p /srv/docker
  chown root:docker /srv/docker
  chmod 2775 /srv/docker
  msg_ok "/srv/docker created (docker group has write access + setgid)"

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

  # Create directory structure following standard
  mkdir -p /srv/docker/dockge/.dockge_data

  # Create docker-compose.yml with custom configuration
  cat > /srv/docker/dockge/docker-compose.yml <<'EOF'
services:
  dockge:
    image: louislam/dockge:1
    container_name: dockge
    restart: unless-stopped
    ports:
      - "5001:5001"
    environment:
      - TZ=Europe/Stockholm
      - DOCKGE_STACKS_DIR=/srv/docker
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./.dockge_data:/app/data
      - /srv/docker:/srv/docker
EOF

  cd /srv/docker/dockge

  if docker compose up -d; then
    cache_server_ip
    msg_ok "Dockge installed successfully"
    echo
    echo "Location: /srv/docker/dockge/"
    echo "Stacks directory: /srv/docker/"
    echo "Access Dockge at: http://$SERVER_IP:5001"
    echo "Create admin account on first login"
    echo
  else
    msg_error "Dockge installation failed"
  fi
}

###########################
# BESZEL MONITORING
###########################

install_beszel() {
  if ! command -v docker >/dev/null; then
    msg_info "Docker not installed. Skipping Beszel."
    return
  fi

  if ! get_yes_no "Install Beszel? (Lightweight server monitoring hub)"; then
    msg_info "Skipping Beszel"
    return
  fi

  msg_info "Installing Beszel..."

  # Create directory structure following standard
  mkdir -p /srv/docker/beszel/.beszel_data

  # Ask if user wants to monitor this server too
  local install_agent=false
  if get_yes_no "Monitor this server? (Install Beszel agent)"; then
    install_agent=true
    echo -n "Enter agent KEY (or press Enter to generate later): "
    read -r agent_key
    echo
  fi

  # Create docker-compose.yml
  if [ "$install_agent" = true ] && [ -n "$agent_key" ]; then
    # Hub + Agent configuration
    cat > /srv/docker/beszel/docker-compose.yml <<EOF
services:
  beszel:
    image: henrygd/beszel
    container_name: beszel
    restart: unless-stopped
    ports:
      - "8090:8090"
    environment:
      - TZ=Europe/Stockholm
    volumes:
      - ./.beszel_data:/beszel_data
    extra_hosts:
      - host.docker.internal:host-gateway

  beszel-agent:
    image: henrygd/beszel-agent
    container_name: beszel-agent
    restart: unless-stopped
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
    environment:
      PORT: 45876
      KEY: "${agent_key}"
EOF
  else
    # Hub only configuration
    cat > /srv/docker/beszel/docker-compose.yml <<'EOF'
services:
  beszel:
    image: henrygd/beszel
    container_name: beszel
    restart: unless-stopped
    ports:
      - "8090:8090"
    environment:
      - TZ=Europe/Stockholm
    volumes:
      - ./.beszel_data:/beszel_data
EOF
  fi

  cd /srv/docker/beszel

  if docker compose up -d; then
    cache_server_ip
    msg_ok "Beszel installed successfully"
    echo
    echo "Location: /srv/docker/beszel/"
    echo "Access Beszel at: http://$SERVER_IP:8090"
    echo "Create admin account on first login"
    if [ "$install_agent" = true ]; then
      echo
      echo "Agent installed on port 45876"
      if [ -z "$agent_key" ]; then
        echo "To configure agent: Add this system in Beszel UI and update KEY in docker-compose.yml"
      fi
    fi
    echo
  else
    msg_error "Beszel installation failed"
  fi
}

###########################
# DOZZLE DOCKER LOGS
###########################

install_dozzle() {
  if ! command -v docker >/dev/null; then
    msg_info "Docker not installed. Skipping Dozzle."
    return
  fi

  if ! get_yes_no "Install Dozzle? (Real-time Docker log viewer with web UI)"; then
    msg_info "Skipping Dozzle"
    return
  fi

  msg_info "Installing Dozzle..."

  # Create directory structure following standard
  mkdir -p /srv/docker/dozzle

  # Create docker-compose.yml
  cat > /srv/docker/dozzle/docker-compose.yml <<'EOF'
services:
  dozzle:
    image: amir20/dozzle:latest
    container_name: dozzle
    restart: unless-stopped
    ports:
      - "8080:8080"
    environment:
      - TZ=Europe/Stockholm
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
EOF

  cd /srv/docker/dozzle

  if docker compose up -d; then
    cache_server_ip
    msg_ok "Dozzle installed successfully"
    echo
    echo "Location: /srv/docker/dozzle/"
    echo "Access Dozzle at: http://$SERVER_IP:8080"
    echo "View real-time logs for all Docker containers"
    echo
  else
    msg_error "Dozzle installation failed"
  fi
}

###########################
# VPN SETUP
###########################

setup_vpn() {
  if ! get_yes_no "Set up Netbird VPN?"; then
    msg_info "Skipping VPN setup"
    return
  fi

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
  command -v glances >/dev/null && echo "• Glances: Installed"
  command -v librespeed-cli >/dev/null && echo "• LibreSpeed-cli: Installed"
  command -v docker >/dev/null && echo "• Docker: Installed ($(docker --version | cut -d' ' -f3 | tr -d ','))"
  docker ps 2>/dev/null | grep -q dockge && echo "• Dockge: Installed (http://$SERVER_IP:5001)"
  docker ps 2>/dev/null | grep -q beszel && echo "• Beszel: Installed (http://$SERVER_IP:8090)"
  docker ps 2>/dev/null | grep -q dozzle && echo "• Dozzle: Installed (http://$SERVER_IP:8080)"
  command -v netbird >/dev/null && echo "• Netbird VPN: Installed"

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
  install_beszel
  install_dozzle
  setup_vpn

  finalize
}

main "$@"
