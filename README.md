# Debian Express Setup

A comprehensive set of scripts for quickly setting up, optimizing, and securing Debian-based servers and VPS instances.

## 🎯 Overview

Three focused scripts that give you full control over what gets installed:
- `deb-express-1-core.sh` - Core configuration & performance optimization
- `deb-express-2-secure.sh` - Security hardening
- `deb-express-3-tools.sh` - Management & monitoring tools

---

## 🚀 Quick Start

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

## 📋 Detailed Features

### 1️⃣ deb-express-1-core.sh - Core Configuration & Performance

**Server Type Detection:**
The script asks if you're running on a VPS/Cloud or Local/Home server and automatically adjusts optimizations accordingly.

**Core System Configuration:**
- ✅ Update and upgrade system packages
- ✅ Configure hostname, timezone, and locale
- ✅ Set/change root password
- ✅ Create non-root user with sudo access

**Performance Optimizations:**
- ✅ **Swap Configuration** - Auto-calculated based on RAM and server type
- ✅ **I/O Scheduler** - Optimized for SSDs/HDDs (local servers only)
- ✅ **Kernel Parameters** - Tuned for VPS or local storage performance
- ✅ **TCP BBR** - Google's congestion control for faster network throughput
- ✅ **File Descriptor Limits** - Increased to 65535 for web servers
- ✅ **Journal Limits** - VPS: 200MB, Local: 500MB
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
- ✅ IP/CIDR whitelist with validation (supports ranges like 192.168.0.0/16)
- ✅ SSH jail protection (5 retries, 10 min ban)

**Automatic Updates:**
- ✅ Daily security updates
- ✅ No automatic reboots (manual control)

**All features are optional with interactive yes/no prompts!**

---

### 3️⃣ deb-express-3-tools.sh - Management & Monitoring

**Monitoring Tools:**
- ✅ **Fastfetch** - Beautiful system information display
- ✅ **Btop** - Modern resource monitor (CPU, RAM, disk, network)
- ✅ **Glances** - Advanced system monitor with web interface
- ✅ **LibreSpeed-cli** - Lightweight internet speed test tool

**Container Management:**
- ✅ **Docker** - Container platform installation
- ✅ **Docker Group Management** - Add users to docker group
- ✅ **/srv/docker Directory** - Auto-creates with docker group permissions + setgid bit
- ✅ **Dockge** - Web UI for Docker Compose stacks (port 5001)
- ✅ **Dozzle** - Real-time Docker log viewer (port 8080)
- ✅ **Beszel** - Lightweight server monitoring hub (port 8090)

**VPN (Remote Access):**
- ✅ **Netbird** - Open-source mesh VPN for secure remote access

**All features are optional with interactive yes/no prompts!**

---

## 🐳 Docker Stack Standard

When Docker is installed via `deb-express-3-tools.sh`, the script automatically sets up a standardized Docker environment:

### Directory Structure
```
/srv/docker/
├── dockge/                    ← Dockge web UI
│   ├── docker-compose.yml
│   └── .dockge_data/          ← hidden persistent data
├── app1/                      ← your Docker stacks
│   ├── docker-compose.yml
│   ├── .env
│   └── .app1_data/
└── app2/
```

### Permissions Setup
- **Owner:** `root:docker`
- **Permissions:** `2775` (rwxrwsr-x)
- **setgid bit enabled:** New files/folders automatically inherit `docker` group
- **Result:** Users in docker group can create/edit/delete without sudo

### Benefits
✅ **No sudo needed** - Docker group members have full access to `/srv/docker`
✅ **Automatic group inheritance** - All new content gets `docker` group ownership
✅ **Clean organization** - All Docker stacks in one standard location
✅ **Hidden data folders** - Cleaner directory listings with `.app_data/` pattern
✅ **Easy backups** - Just backup `/srv/docker`

---

## ⚡ VPS vs Local Server Optimizations

The core script automatically adjusts optimizations based on your server type:

| Optimization | VPS/Cloud | Local/Home Server |
|--------------|-----------|-------------------|
| **Swap Size** | Conservative (4GB cap) | Generous (up to 8GB) |
| **I/O Scheduler** | Skipped (hypervisor handles) | Tuned for SSD/HDD |
| **Dirty Ratio** | 5% (flush sooner) | 10% (more buffer) |
| **Dirty BG Ratio** | 3% | 5% |
| **Journal Size** | 200MB | 500MB |

### Swap Recommendations by RAM

| RAM | VPS | Local |
|-----|-----|-------|
| <2GB | 2x RAM | 2x RAM |
| 2-4GB | 1x RAM | 1x RAM |
| 4-8GB | 4GB | 4GB |
| 8-16GB | 4GB | 8GB |
| >16GB | 4GB | 8GB |

**Why the difference?**
- **VPS**: Disk I/O is typically slower (shared/network storage), so we flush dirty pages sooner and use less swap
- **Local**: Fast local SSDs benefit from larger buffers and can handle more swap without performance issues

---

## 🎯 Key Features

✅ **Full Control** - Every feature requires your approval
✅ **Modular Design** - Run only what you need
✅ **Clear Order** - Numbered scripts show execution sequence
✅ **Smart Detection** - Auto-detects RAM, OS, SSD/HDD, VPS vs Local
✅ **Server-Aware** - Different optimizations for VPS vs home servers
✅ **Input Validation** - Validates IPs, ports, CIDR ranges
✅ **Docker Standard** - Automatic `/srv/docker` setup with proper permissions

---

## 🔧 Requirements

- **OS**: Debian 10+, Ubuntu 20.04+, or any Debian-based distribution
- **Privileges**: Root access (or sudo)
- **Connection**: Internet connection for package downloads

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
- **After being added to docker group:** Logout and login again, or run `newgrp docker`
- **Check group membership:** `groups` or `id`
- **Verify /srv/docker permissions:** `ls -ld /srv/docker` should show `drwxrwsr-x root docker`
- **Test write access:** `touch /srv/docker/test.txt` (should work without sudo)
- **If permission denied:** Ensure you're in docker group and have logged in again

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

## 🔄 Recent Updates

### Latest Changes (January 2026)
- ✅ **Removed Old Scripts** - Deprecated `debian-express-setup.sh` and `debian-express-secure.sh` removed
- ✅ **VPS vs Local Server Detection** - Script now asks server type and adjusts optimizations accordingly
- ✅ **Improved Swap Recommendations** - Conservative 4GB cap for VPS, up to 8GB for local servers
- ✅ **I/O Scheduler** - Skipped for VPS (hypervisor handles it), tuned for local servers
- ✅ **Kernel Tuning** - Different dirty ratios for VPS (5%/3%) vs local (10%/5%)
- ✅ **Journal Limits** - VPS: 200MB, Local: 500MB
- ✅ **New Monitoring Tools** - Added Glances, LibreSpeed-cli, Dozzle, and Beszel
- ✅ **Improved UX** - Better prompts for firewall enable and passwordless sudo user selection
- ✅ **Docker Stack Standard** - Automatic `/srv/docker` creation with docker group + setgid permissions

Check the [releases page](https://github.com/eviipx/debian-express-setup/releases) for full update history.
