# Debian Express Setup

A comprehensive set of scripts for quickly setting up, optimizing, and securing Debian-based servers and VPS instances.

## Features

This project consists of two complementary scripts that work together:

### Script 1: debian-express-setup.sh (System Setup & Optimization)
- **Core System Configuration**: Update packages, set hostname, timezone, locale
- **System Optimization**: Configure swap, I/O scheduler, kernel parameters
- **Management Tools**: Install Webmin/Easy Panel, monitoring tools
- **Container Support**: Set up Docker and Dockge container manager

### Script 2: debian-express-secure.sh (Security & Network)
- **SSH Hardening**: Configure SSH keys, disable root login, and more
- **Firewall Setup**: Configure UFW with automatic detection of installed services
- **Intrusion Prevention**: Set up Fail2Ban to block brute force attempts
- **VPN Integration**: Configure Tailscale or Netbird for secure remote access
- **Automatic Updates**: Schedule security updates and optional reboots

## Quick Start

For best results, run the scripts in order: first the setup script, then the security script.

### Option 1: Run directly (for trusted environments)

# Run the system setup script
```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-setup.sh)"
```
```bash
# Then run the security script
bash -c "$(curl -fsSL https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-secure.sh)"
```

### Option 2: Download, review, and run (recommended)

```bash
# Update packages
apt update && apt upgrade -y

# Install curl if not already installed
apt install -y curl

# Download the scripts
curl -fsSL -o debian-express-setup.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-setup.sh
curl -fsSL -o debian-express-secure.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-secure.sh

# Review the scripts before running (recommended)
less debian-express-setup.sh
less debian-express-secure.sh

# Make the scripts executable
chmod +x debian-express-setup.sh debian-express-secure.sh

# Run the system setup script
sudo ./debian-express-setup.sh

# After the system setup completes (and optionally rebooting), run the security script
sudo ./debian-express-secure.sh
