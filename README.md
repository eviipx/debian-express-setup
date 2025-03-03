# Debian Express Setup

A comprehensive bash script for quickly setting up and securing Debian-based servers and VPS instances.

## Features

- **Core System Configuration**: Update packages, set hostname, timezone, locale, and swap
- **User Management**: Create non-root users, configure sudo access
- **SSH Hardening**: Configure SSH keys, disable root login, and more
- **Firewall Setup**: Configure UFW with secure defaults
- **Brute Force Protection**: Install and configure Fail2Ban
- **VPN Integration**: Set up Tailscale or Netbird for secure remote access
- **System Optimization**: Configure performance parameters
- **Monitoring Tools**: Install btop, speedtest-cli, and more
- **Log Management**: Set up Logwatch for daily reports
- **Container Support**: Install Docker and Dockge (container management UI)
- **Backup Tools**: Install Restic for backups

## Quick Start

### Option 1: Run directly (for trusted environments)

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/yourusername/debian-express-setup/main/debian-express-setup.sh)"
```

### Option 2: Download, review, and run (recommended)

```bash
# Update packages
apt update && apt upgrade -y

# Install curl if not already installed
apt install -y curl

# Download the script
curl -fsSL -o debian-express-setup.sh https://raw.githubusercontent.com/yourusername/debian-express-setup/main/debian-express-setup.sh

# Review the script (always review scripts before running them)
less debian-express-setup.sh

# Make it executable
chmod +x debian-express-setup.sh

# Run the script
sudo ./debian-express-setup.sh
