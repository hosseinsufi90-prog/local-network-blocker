# NetGuard

NetGuard is a local network device manager for monitoring and controlling devices connected to a private Wi‑Fi or LAN.

It scans the network, identifies connected devices, and displays key information including IP address, MAC address, vendor, hostname, device type, and activity history. It also detects new devices, lets users label known devices, and supports blocking or unblocking access through ARP-based protection.

## Features
- Scans local network devices
- Displays device information: IP, MAC, vendor, type, hostname
- Tracks first-seen and last-seen timestamps
- Detects new devices joining the network
- Allows renaming and labeling devices
- Blocks/unblocks devices via ARP spoofing
- Supports mobile access on the same network via Flask dashboard
- Exports device list to CSV

## Important Note
This project is intended only for networks you own or administer. Use responsibly and only in authorized environments.

## Requirements
```bash
pip install -r requirements.txt
```

## Run on Windows
Double-click `Run_NetGuard.bat` or run:

```bash
python gui_app.py
```

## Notes
Some features, especially the mobile dashboard and related workflow, may still require further testing and refinement.
