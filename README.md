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
