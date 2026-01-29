# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Debian Express Setup is a collection of bash scripts for setting up, optimizing, and securing Debian-based servers and VPS instances. Three focused scripts that run in order:

- `deb-express-1-core.sh` - Core configuration & performance optimization (VPS vs Local aware)
- `deb-express-2-secure.sh` - Security hardening (SSH, firewall, Fail2Ban)
- `deb-express-3-tools.sh` - Management & monitoring tools (Docker, Dockge, Glances, Dozzle, Beszel, Netbird)

## Testing Scripts

Scripts must be tested on actual Debian/Ubuntu systems (VMs or containers). There are no automated tests. To test:

```bash
# Make scripts executable
chmod +x deb-express-*.sh

# Run as root (scripts check for root privileges)
sudo ./deb-express-1-core.sh
```

## Code Architecture

### Script Structure Pattern

All scripts follow the same structure:
1. Color definitions and formatting (`RD`, `GN`, `YW`, `BL`, `CL`, etc.)
2. Helper functions (`msg_ok`, `msg_info`, `msg_error`, `get_yes_no`)
3. Root and OS validation (`check_root`, `check_debian_based`, `detect_os`)
4. Feature-specific functions (grouped by section)
5. Summary display function
6. `main()` function that orchestrates the flow

### Shared Conventions

- **Interactive prompts**: All features use `get_yes_no()` for user confirmation
- **Color output**: Use `${HIGHLIGHT}value${CL}` for highlighted text, `msg_ok/msg_info/msg_error` for status
- **OS detection**: Scripts differentiate between Ubuntu (PPAs available) and Debian (standard repos)
- **State sharing**: `/tmp/debian-express/` is used for inter-script communication (e.g., `installed-services.txt`)
- **Summary files**: Security summary saved to `/root/debian-express-security-summary.txt`

### Key Functions to Know

- `validate_ip_or_cidr()` - Validates IP addresses and CIDR ranges (e.g., `192.168.0.0/16`)
- `validate_port()` - Validates port numbers (1-65535)
- `cache_server_ip()` - Caches hostname IP to avoid repeated lookups
- `run_apt_update()` - Runs apt update only once per session (uses `APT_UPDATED` flag)

## Docker Stack Standard

When Docker is installed via `deb-express-3-tools.sh`, it creates `/srv/docker/` with:
- Owner: `root:docker`
- Permissions: `2775` (setgid bit for automatic group inheritance)
- Dockge installed at `/srv/docker/dockge/` managing stacks in `/srv/docker/`
- Hidden data folders pattern: `.app_data/`

## Requirements

- **OS**: Debian 10+, Ubuntu 20.04+, or any Debian-based distribution
- **Privileges**: Root access required
- **Connection**: Internet connection for package downloads
