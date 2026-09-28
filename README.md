# Network Monitor

A lightweight scanner that finds every device on your local network and lists each one's IP address, MAC address, and hostname. You can run it from the command line or view the results in the browser.

## Features

- **Detects your network automatically.** Works out your local IP and scans the surrounding `/24` subnet, so there is nothing to configure.
- **Discovers devices with ARP.** Broadcasts ARP requests with [Scapy](https://scapy.net/) and records every device that answers.
- **Resolves hostnames.** Does a reverse DNS lookup on each device, and falls back to `Unknown` when there is no name.
- **Two ways to use it.** A command-line scan that saves results to JSON, and a small [Flask](https://flask.palletsprojects.com/) web page that runs a fresh scan each time you load it.

## How it works

1. `NetworkScan` finds the machine's local IP by opening a UDP socket toward a public address. No packets are sent; this only asks the OS which interface it would route through. It then derives the `x.x.x.0/24` range from that IP.
2. It broadcasts an ARP "who-has" request to every address in the range (`ff:ff:ff:ff:ff:ff`).
3. For each reply, it records the sender's IP and MAC address and tries a reverse DNS lookup for the hostname.
4. The command-line script writes the results to `network_devices.json`. The Flask app renders them as a web page.

## Requirements

- Python 3.8+
- `scapy` and `flask`
- **Administrator / root privileges.** Scapy needs raw socket access to send ARP packets.
- **Windows only:** [Npcap](https://npcap.com/) (install it with "WinPcap API-compatible mode" enabled)

## Installation

```bash
git clone https://github.com/Jhoneks/Network-Monitor.git
cd Network-Monitor
pip install scapy flask
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

Example output:

```
NETWORK DEVICE SCANNER
Your local IP: 192.168.1.23
Scanning network: 192.168.1.0/24
...
192.168.1.1       a4:2b:b0:xx:xx:xx   router.local
192.168.1.23      3c:22:fb:xx:xx:xx   my-laptop
192.168.1.40      b8:27:eb:xx:xx:xx   Unknown

 Summary: Successfully found 3 device(s)
 Results saved to: network_devices.json
```

The results are saved as JSON:

```json
[
  { "IP": "192.168.1.1", "MAC": "a4:2b:b0:xx:xx:xx", "Hostname": "router.local" }
]
```

### Web view

```bash
# Linux / macOS
sudo python3 "network load.py"

# Windows (run the terminal as Administrator)
python "network load.py"
```

Then open <http://127.0.0.1:5000>. Each page load runs a new scan, so the page takes a few seconds to appear.

## Limitations

- Scans only a `/24` subnet (256 addresses) based on the local IP.
- Devices that ignore ARP, or that are asleep, may not appear.
- A hostname appears only when the network's DNS has a reverse record for the device.
- The web view runs a blocking scan on every request and is intended for local use only.

## Roadmap

- [ ] Add a `requirements.txt`
- [ ] Support custom subnets from the command line (e.g. `--network 10.0.0.0/24`)
- [ ] Look up the manufacturer from the MAC address (OUI lookup)
- [ ] Alert when a new, unrecognised device joins the network
- [ ] Improve the web view with a table and auto-refresh

## Responsible use

Only scan networks you own or have explicit permission to test. Scanning networks without authorisation may breach acceptable-use policies or the law.

## Author

**Jhonathan Nelson**, [GitHub](https://github.com/Jhoneks)
