# Network Monitor

A lightweight scanner that finds every device on your local network and lists each one's IP address, MAC address, and hostname. You can run it from the command line or view the results in the browser.

## Features

- **Detects your network automatically.** Works out your local IP and scans the surrounding `/24` subnet, so there is nothing to configure. You can also pass any subnet with `--network`.
- **Works with a VPN on.** Picks your physical Wi-Fi or Ethernet adapter from the routing table and sends ARP straight out of it, so a VPN tunnel doesn't hide your home network.
- **Discovers devices with ARP.** Broadcasts ARP requests with [Scapy](https://scapy.net/) and records every device that answers.
- **Resolves hostnames.** Tries system DNS, then the router's DNS directly, then mDNS (Bonjour), then NetBIOS, for all devices at once. Falls back to `Unknown` when a device doesn't publish a name.
- **Identifies the manufacturer.** Looks up the vendor from the MAC address and flags randomised (private) MACs, which phones and tablets use.
- **Detects client isolation.** When only your machine and the router answer, it sends an mDNS probe for devices the scan couldn't reach. If one replies, the network is hiding devices from each other (client/AP isolation); if none do, it's likely just the two of you online. Only runs in that two-device case, so normal scans aren't slowed.
- **Two ways to use it.** A command-line scan that saves results to JSON, and a small [Flask](https://flask.palletsprojects.com/) web page that shows the last scan in a table and rescans on demand.

## How it works

1. `NetworkScan` reads the routing table and picks the private subnet attached directly to a physical adapter, preferring the one with a default gateway (your router). VPN and virtual adapters (WireGuard, OpenVPN, Tailscale, AnyConnect, Hyper-V, VMware and so on) are skipped. If no physical adapter is found, it falls back to asking the OS which interface reaches the internet. Pass `--network` or `--iface` to choose yourself.
2. It broadcasts an ARP "who-has" request to every address in the range (`ff:ff:ff:ff:ff:ff`) on that adapter. ARP isn't routed over IP, so it doesn't go through the VPN tunnel.
3. For each reply, it records the sender's IP and MAC address, looks up the vendor from the MAC, and tries each hostname method in turn until one answers.
4. The command-line script writes the results to `network_devices.json`. The Flask app caches them and renders them as a table.

## Requirements

- Python 3.8+
- `scapy` and `flask` (listed in `requirements.txt`)
- **Administrator / root privileges.** Scapy needs raw socket access to send ARP packets.
- **Windows only:** [Npcap](https://npcap.com/) (install it with "WinPcap API-compatible mode" enabled)

## Installation

```bash
git clone https://github.com/Jhoneks/Network-Monitor.git
cd Network-Monitor
pip install -r requirements.txt
```

## Usage

Run the commands from the `network model` folder.

```bash
cd "network model"
```

### Command line

```bash
# Linux / macOS
sudo python3 network_monitoring.py

# Windows (run the terminal as Administrator)
python network_monitoring.py
```

Options:

| Option | Default | Description |
| --- | --- | --- |
| `-n`, `--network` | auto-detected | Network to scan in CIDR form, e.g. `10.0.0.0/16`. A bare IP is treated as `/24`. |
| `-i`, `--iface` | auto-detected | Network adapter to scan from, e.g. `Wi-Fi` or `eth0`. |
| `-t`, `--timeout` | `5` | Seconds to wait for ARP replies. |
| `-r`, `--retry` | `3` | Times to resend requests that got no reply. |
| `-o`, `--output` | `network_devices.json` | File to save the results to. |

```bash
sudo python3 network_monitoring.py --network 10.0.0.0/22 --timeout 8
```

Example output:

```
NETWORK DEVICE SCANNER
Your local IP: 192.168.1.23
Scanning network: 192.168.1.0/24
...
192.168.1.1       a4:2b:b0:xx:xx:xx   router.local            Arcadyan Corporation
192.168.1.23      3c:22:fb:xx:xx:xx   my-laptop               Apple, Inc.
192.168.1.40      b8:27:eb:xx:xx:xx   Unknown                 Raspberry Pi Foundation

 Summary: Successfully found 3 device(s)
 Results saved to: network_devices.json
```

The results are saved as JSON:

```json
[
  { "IP": "192.168.1.1", "MAC": "a4:2b:b0:xx:xx:xx", "Hostname": "router.local", "Vendor": "Arcadyan Corporation" }
]
```

### Web view

```bash
# Linux / macOS
sudo python3 "network load.py"

# Windows (run the terminal as Administrator)
python "network load.py"
```

Your browser opens <http://127.0.0.1:5000> automatically; if it doesn't, open that address yourself. The first page load runs a scan, so it takes a few seconds to appear. After that the page shows the cached results instantly; click **Scan again** to refresh them.

## Limitations

- ARP works only on the local link, so it can't discover devices behind a router. Large ranges (e.g. `/16`) are also slow to scan.
- Devices that ignore ARP, or that are asleep, may not appear. Raising `--timeout` or `--retry` helps with slow devices.
- A hostname appears only when the router's DNS knows the device, or the device answers mDNS or NetBIOS. Many phones, smart TVs and IoT devices do none of these; the Vendor column helps identify them instead.
- The web view listens on `127.0.0.1` only and is meant for local use. Clicking **Scan again** still blocks until the scan finishes.
- Auto-detection is IPv4 only. Subnets larger than `/22` are narrowed to the `/24` around your IP; use `--network` to scan the whole range.
- A VPN with "block local network access" (a kill switch or LAN blocking) may still stop replies. Allow LAN access in the VPN settings.
- Client-isolation detection is best-effort: a confirmed hit is reliable, but a device that is asleep or doesn't speak mDNS can't always be told apart from an empty network.
- With a VPN on, the system DNS lookup goes to the VPN's DNS server. The scanner then asks your router directly, but some VPNs block that too.

## Roadmap

- [x] Add a `requirements.txt`
- [x] Support custom subnets from the command line (e.g. `--network 10.0.0.0/24`)
- [x] Look up the manufacturer from the MAC address (OUI lookup)
- [x] Detect client isolation and tell it apart from a genuinely near-empty network
- [ ] Alert when a new, unrecognised device joins the network
- [x] Show the web view results in a table
- [ ] Auto-refresh the web view in the background

## Responsible use

Only scan networks you own or have explicit permission to test. Scanning networks without authorisation may breach acceptable-use policies or the law.

## Author

**Jhonathan Nelson**, [GitHub](https://github.com/Jhoneks)
