# Debian Express Setup

A comprehensive set of scripts for quickly setting up, optimizing, and securing Debian-based servers and VPS instances.

## 🎯 Overview

This project provides **two approaches** for server setup:

### ✨ **New Modular Scripts** (Recommended)
Three focused scripts that give you full control over what gets installed:
- `deb-express-1-core.sh` - Core configuration & performance optimization
- `deb-express-2-secure.sh` - Security hardening
- `deb-express-3-tools.sh` - Management & monitoring tools

### 📦 **Original Scripts** (Backward Compatible)
Two comprehensive scripts that handle everything:
- `debian-express-setup.sh` - System setup & optimization
- `debian-express-secure.sh` - Security & network configuration

---

## 🚀 Quick Start (New Modular Scripts)

### Option 1: Download and Run (Recommended)

```bash
# Update packages and install curl
apt update && apt upgrade -y && apt install -y curl

# Download all three scripts
curl -fsSL -o deb-express-1-core.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-1-core.sh
curl -fsSL -o deb-express-2-secure.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-2-secure.sh
curl -fsSL -o deb-express-3-tools.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-3-tools.sh

# Make executable
chmod +x deb-express-*.sh

# Run in order (each script is interactive)
sudo ./deb-express-1-core.sh      # Core config & performance
sudo reboot                         # Recommended after core setup
sudo ./deb-express-2-secure.sh    # Security hardening
sudo ./deb-express-3-tools.sh     # Optional: Install tools
```

### Option 2: Run Directly

```bash
# Step 1: Core configuration and performance
bash -c "$(curl -fsSL https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-1-core.sh)"

# Step 2: Security hardening (after reboot)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-2-secure.sh)"

# Step 3: Management tools (optional)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/eviipx/debian-express-setup/main/deb-express-3-tools.sh)"
```

---

## 📋 New Modular Scripts - Detailed Features

### 1️⃣ deb-express-1-core.sh - Core Configuration & Performance

**Core System Configuration:**
- ✅ Update and upgrade system packages
- ✅ Configure hostname, timezone, and locale
- ✅ Set/change root password
- ✅ Create non-root user with sudo access

**Performance Optimizations:**
- ✅ **Swap Configuration** - Auto-calculated based on RAM size
- ✅ **I/O Scheduler** - Optimized for SSDs and HDDs
- ✅ **Kernel Parameters** - Improved file system, network, and responsiveness
- ✅ **TCP BBR** - Google's congestion control for faster network throughput
- ✅ **File Descriptor Limits** - Increased to 65535 for web servers
- ✅ **Journal Limits** - Prevents logs from consuming too much disk space
- ✅ **Service Cleanup** - Disables unused services (Bluetooth, printing, etc.)
- ✅ **Nohang** - Prevents system freezes (only for systems with <16GB RAM)
- ✅ **IPv6 Control** - Option to disable if not needed
- ✅ **tmpfs for /tmp** - RAM-based temp directory (auto-sized by RAM)

**All features are optional with interactive yes/no prompts!**

---

### 2️⃣ deb-express-2-secure.sh - Security & Hardening

**SSH Hardening:**
- ✅ Create non-root user (if needed)
- ✅ Set up SSH key authentication
- ✅ Disable root SSH login
- ✅ Disable password authentication (when using SSH keys)
- ✅ Configure passwordless sudo

**Firewall (UFW):**
- ✅ Basic rules: Allow SSH, deny incoming, allow outgoing
- ✅ Web traffic options (HTTP/HTTPS)
- ✅ Custom port rules with TCP/UDP selection
- ✅ Port validation (1-65535)

**Intrusion Prevention:**
- ✅ Fail2Ban installation and configuration
- ✅ IP/CIDR whitelist with validation
- ✅ SSH jail protection (5 retries, 10 min ban)

**VPN Integration:**
- ✅ Tailscale setup
- ✅ Netbird setup

**Automatic Updates:**
- ✅ Daily security updates
- ✅ No automatic reboots (manual control)

**All features are optional with interactive yes/no prompts!**

---

### 3️⃣ deb-express-3-tools.sh - Management & Monitoring

**Monitoring Tools:**
- ✅ **Fastfetch** - Beautiful system information display
- ✅ **Btop** - Modern resource monitor (CPU, RAM, disk, network)
- ✅ **Speedtest-cli** - Internet speed testing

**Container Management:**
- ✅ **Docker** - Container platform installation
- ✅ **Docker Group Management** - Add users to docker group
- ✅ **Dockge** - Web UI for Docker Compose stacks (port 5001)

**All features are optional with interactive yes/no prompts!**

---

## 🎯 Why Use the New Modular Scripts?

✅ **Full Control** - Every feature requires your approval
✅ **Modular Design** - Run only what you need
✅ **Clear Order** - Numbered scripts show execution sequence
✅ **Better Organization** - Each script has a focused purpose
✅ **Easy Maintenance** - Simpler to update and customize
✅ **Smart Detection** - Auto-detects RAM, OS, SSD/HDD
✅ **Input Validation** - Validates IPs, ports, CIDR ranges

---

## 📦 Original Scripts (Backward Compatible)

The original comprehensive scripts are still available and fully functional:

### debian-express-setup.sh
Handles system setup, optimization, and container management in one script.

### debian-express-secure.sh
Handles SSH hardening, firewall, Fail2Ban, VPN, and auto-updates in one script.

### Quick Start (Original Scripts)

```bash
# Download
curl -fsSL -o debian-express-setup.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-setup.sh
curl -fsSL -o debian-express-secure.sh https://raw.githubusercontent.com/eviipx/debian-express-setup/main/debian-express-secure.sh

# Make executable
chmod +x debian-express-setup.sh debian-express-secure.sh

# Run in order
sudo ./debian-express-setup.sh
sudo ./debian-express-secure.sh
```

---

## 🔧 Requirements

- **OS**: Debian 10+, Ubuntu 20.04+, or any Debian-based distribution
- **Privileges**: Root access (or sudo)
- **Connection**: Internet connection for package downloads

---

## 📊 Comparison: New vs Original Scripts

| Feature | New Modular Scripts | Original Scripts |
|---------|---------------------|------------------|
| **Number of Scripts** | 3 focused scripts | 2 comprehensive scripts |
| **User Control** | Every feature optional | Less granular control |
| **Organization** | Clear separation of concerns | All-in-one approach |
| **Execution Order** | Numbered (1, 2, 3) | Sequential (setup, secure) |
| **Performance Optimizations** | 10 optimizations | 4 optimizations |
| **Flexibility** | Run any script independently | Must run both |
| **Best For** | Users who want control | Users who want automation |

---

## 💡 Recommendations

### For Homelab Servers (16GB+ RAM):
```bash
./deb-express-1-core.sh    # Yes to most, skip nohang
./deb-express-2-secure.sh  # Configure SSH keys and firewall
./deb-express-3-tools.sh   # Install Docker and monitoring tools
```

### For Small VPS (4-8GB RAM):
```bash
./deb-express-1-core.sh    # Yes to all optimizations
./deb-express-2-secure.sh  # Essential security hardening
./deb-express-3-tools.sh   # Optional, skip if tight on resources
```

### For Production Servers:
```bash
./deb-express-1-core.sh    # Careful with optimizations, test first
./deb-express-2-secure.sh  # Mandatory security hardening
./deb-express-3-tools.sh   # Install monitoring, skip Docker if not needed
```

---

## 🛡️ Security Best Practices

1. **Always review scripts** before running them with root privileges
2. **Test SSH access** in a new terminal before closing your current session
3. **Keep a backup** of important configuration files
4. **Document your choices** for future reference
5. **Update regularly** by re-running the scripts with updated versions

---

## 🐛 Troubleshooting

### SSH Connection Issues After Security Script
- Make sure you tested SSH with a new connection before closing your session
- Check firewall rules: `sudo ufw status`
- Check SSH config: `sudo sshd -T | grep -E 'permit|auth'`

### Performance Issues After Optimization
- Review applied optimizations in the summary
- Revert specific changes by editing `/etc/sysctl.d/99-performance.conf`
- Check journal size: `journalctl --disk-usage`

### Docker Permission Issues
- Logout and login again after being added to docker group
- Or run: `newgrp docker`

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file for details

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

---

## ⭐ Support

If you find these scripts helpful, please give this repository a star!

---

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

## 🔄 Updates

Check the [releases page](https://github.com/eviipx/debian-express-setup/releases) for the latest updates and changelogs.
